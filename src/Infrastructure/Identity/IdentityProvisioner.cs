using AMDN.Identity.Membership;
using Npgsql;

namespace AMDN.Infrastructure.Identity;

// Trusted internal primitive, not a public registration API or an authorization decision.
public sealed class IdentityProvisioner(NpgsqlDataSource provisioningDatabase)
{
    public async Task<Guid> CreateTenantAsync(CancellationToken cancellationToken = default)
    {
        await using var command = provisioningDatabase.CreateCommand("INSERT INTO amdn_identity.tenants DEFAULT VALUES RETURNING tenant_id");
        return (Guid)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    public async Task<PersonalPostman> EnsureMemberAsync(Guid tenant, string issuer, string subject, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(issuer) || issuer.Length > 2048 || issuer.Contains('\0')
            || string.IsNullOrWhiteSpace(subject) || subject.Length > 255 || subject.Contains('\0'))
            throw new ArgumentException("A bounded issuer and subject are required.");
        await using var connection = await provisioningDatabase.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        // Low-volume provisioning serializes per tenant. No read-then-insert race.
        await using var gate = new NpgsqlCommand("SELECT status FROM amdn_identity.tenants WHERE tenant_id=@tenant FOR UPDATE", connection, transaction);
        gate.Parameters.AddWithValue("tenant", tenant);
        if (await gate.ExecuteScalarAsync(cancellationToken) is not "active")
            throw new InvalidOperationException("An active tenant is required.");
        PersonalPostman? result = null;
        await using (var existing = new NpgsqlCommand("""
            SELECT m.user_id,p.postman_id,u.identity_version,m.membership_version,p.policy_version,
                   m.status='active' AND u.status='active' AND p.status='active'
            FROM amdn_identity.memberships m JOIN amdn_identity.users u USING (tenant_id,user_id)
              JOIN amdn_identity.postmen p ON p.tenant_id=m.tenant_id AND p.owner_user_id=m.user_id
            WHERE m.tenant_id=@tenant AND m.issuer=@issuer AND m.subject=@subject
            FOR SHARE OF m,u,p
            """, connection, transaction))
        {
            existing.Parameters.AddWithValue("tenant", tenant);
            existing.Parameters.AddWithValue("issuer", issuer);
            existing.Parameters.AddWithValue("subject", subject);
            await using var rows = await existing.ExecuteReaderAsync(cancellationToken);
            if (await rows.ReadAsync(cancellationToken))
            {
                if (!rows.GetBoolean(5)) throw new InvalidOperationException("Inactive identities cannot be re-enrolled implicitly.");
                result = new PersonalPostman(tenant, rows.GetGuid(0), rows.GetGuid(1), rows.GetInt64(2), rows.GetInt64(3), rows.GetInt64(4));
            }
        }
        if (result is null)
        {
            await using var createUser = new NpgsqlCommand("INSERT INTO amdn_identity.users (tenant_id) VALUES (@tenant) RETURNING user_id", connection, transaction);
            createUser.Parameters.AddWithValue("tenant", tenant);
            var user = (Guid)(await createUser.ExecuteScalarAsync(cancellationToken))!;
            await using var bind = new NpgsqlCommand("INSERT INTO amdn_identity.memberships (tenant_id,user_id,issuer,subject) VALUES (@tenant,@user,@issuer,@subject)", connection, transaction);
            bind.Parameters.AddWithValue("tenant", tenant);
            bind.Parameters.AddWithValue("user", user);
            bind.Parameters.AddWithValue("issuer", issuer);
            bind.Parameters.AddWithValue("subject", subject);
            await bind.ExecuteNonQueryAsync(cancellationToken);
            await using var postman = new NpgsqlCommand("INSERT INTO amdn_identity.postmen (tenant_id,owner_user_id) VALUES (@tenant,@user) RETURNING postman_id", connection, transaction);
            postman.Parameters.AddWithValue("tenant", tenant);
            postman.Parameters.AddWithValue("user", user);
            result = new PersonalPostman(tenant, user, (Guid)(await postman.ExecuteScalarAsync(cancellationToken))!, 1, 1, 1);
        }
        await transaction.CommitAsync(cancellationToken);
        return result;
    }
}
