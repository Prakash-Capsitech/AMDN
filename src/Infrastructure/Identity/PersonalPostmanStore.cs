using System.Security.Claims;
using AMDN.Identity.Membership;
using Npgsql;
using NpgsqlTypes;

namespace AMDN.Infrastructure.Identity;

public sealed class PersonalPostmanStore(NpgsqlDataSource runtimeDatabase) : IPersonalPostmanStore
{
    // This library trusts only the principal produced by the configured authentication pipeline.
    // It is not an operation authorization policy; F1.3 must gate each exposed API.
    public Task<PersonalPostman?> ReadAsync(ClaimsPrincipal caller, Guid? selectedTenant = null, CancellationToken cancellationToken = default) =>
        Read(caller, selectedTenant, false, cancellationToken);

    public Task<PersonalPostman?> ReadOwnerAsync(ClaimsPrincipal caller, Guid selectedTenant, CancellationToken cancellationToken = default) =>
        IdentityScopes.Has(caller, "postman.read") ? Read(caller, selectedTenant, true, cancellationToken) : Task.FromResult<PersonalPostman?>(null);

    private async Task<PersonalPostman?> Read(ClaimsPrincipal caller, Guid? selectedTenant, bool requireGrant, CancellationToken cancellationToken)
    {
        var subject = VerifiedExternalSubject.FromPrincipal(caller);
        if (subject is null) return null;
        await using var connection = await runtimeDatabase.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        Guid tenant, user, postman;
        await using (var resolve = new NpgsqlCommand("SELECT * FROM amdn_identity.resolve_membership(@issuer,@subject,@selected)", connection, transaction))
        {
            resolve.Parameters.AddWithValue("issuer", subject.Issuer);
            resolve.Parameters.AddWithValue("subject", subject.Subject);
            resolve.Parameters.AddWithValue("selected", NpgsqlDbType.Uuid, (object?)selectedTenant ?? DBNull.Value);
            await using var rows = await resolve.ExecuteReaderAsync(cancellationToken);
            if (!await rows.ReadAsync(cancellationToken)) return null;
            (tenant, user, postman) = (rows.GetGuid(0), rows.GetGuid(1), rows.GetGuid(2));
            if (await rows.ReadAsync(cancellationToken)) return null; // Explicit selection required for multiple memberships.
        }
        await using (var context = new NpgsqlCommand("""
            SELECT set_config('amdn.tenant_id',@tenant,true),set_config('amdn.user_id',@user,true),
                   set_config('amdn.issuer',@issuer,true),set_config('amdn.subject',@subject,true)
            """, connection, transaction))
        {
            context.Parameters.AddWithValue("tenant", tenant.ToString());
            context.Parameters.AddWithValue("user", user.ToString());
            context.Parameters.AddWithValue("issuer", subject.Issuer);
            context.Parameters.AddWithValue("subject", subject.Subject);
            await context.ExecuteNonQueryAsync(cancellationToken);
        }
        if (requireGrant)
        {
            await using var grant = new NpgsqlCommand("SELECT amdn_identity.lock_owner_grant(@tenant,@user,@postman)", connection, transaction);
            grant.Parameters.AddWithValue("tenant", tenant);
            grant.Parameters.AddWithValue("user", user);
            grant.Parameters.AddWithValue("postman", postman);
            if (await grant.ExecuteScalarAsync(cancellationToken) is not true) return null;
        }
        PersonalPostman result;
        await using (var query = new NpgsqlCommand("""
            SELECT u.identity_version,m.membership_version,p.policy_version,p.receive_enabled,p.dispatch_enabled,p.retry_enabled FROM amdn_identity.postmen p
              JOIN amdn_identity.users u ON u.tenant_id=p.tenant_id AND u.user_id=p.owner_user_id
              JOIN amdn_identity.memberships m ON m.tenant_id=u.tenant_id AND m.user_id=u.user_id
            WHERE p.tenant_id=@tenant AND p.postman_id=@postman
            """, connection, transaction))
        {
            query.Parameters.AddWithValue("tenant", tenant);
            query.Parameters.AddWithValue("postman", postman);
            await using var rows = await query.ExecuteReaderAsync(cancellationToken);
            if (!await rows.ReadAsync(cancellationToken)) return null;
            result = new PersonalPostman(tenant, user, postman, rows.GetInt64(0), rows.GetInt64(1), rows.GetInt64(2), rows.GetBoolean(3), rows.GetBoolean(4), rows.GetBoolean(5));
        }
        await transaction.CommitAsync(cancellationToken);
        return result;
    }
}
