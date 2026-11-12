using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AMDN.Identity.Membership;
using Npgsql;
using NpgsqlTypes;

namespace AMDN.Infrastructure.Identity;

public sealed record ProvisioningResult(int Status, Guid? TenantId = null, Guid? UserId = null, Guid? PostmanId = null);

// Only the separately deployed provisioning host receives this service/credential.
public sealed class PlatformProvisioner(NpgsqlDataSource database)
{
    public Task<ProvisioningResult> CreateTenantAsync(ClaimsPrincipal caller, string key, byte[] body,
        string displayName, int memberLimit, CancellationToken cancellationToken) =>
        Execute(caller, key, body, null, displayName, memberLimit, null, null, cancellationToken);

    public Task<ProvisioningResult> EnrollAsync(ClaimsPrincipal caller, string key, byte[] body, Guid tenant,
        string issuer, string subject, CancellationToken cancellationToken) =>
        Execute(caller, key, body, tenant, null, 0, issuer, subject, cancellationToken);

    private async Task<ProvisioningResult> Execute(ClaimsPrincipal caller, string key, byte[] body, Guid? selectedTenant,
        string? displayName, int memberLimit, string? issuer, string? subject, CancellationToken ct)
    {
        var operation = selectedTenant is null ? "tenant.provision" : "membership.provision";
        var actor = VerifiedExternalSubject.FromPrincipal(caller);
        if (actor is null || !IdentityScopes.Has(caller, operation)) return new(403);
        if (key.Length is < 16 or > 128 || key.Any(c => c < 0x21 || c > 0x7e) || body.Length is 0 or > 16384)
            return new(400);
        if (selectedTenant is null && (string.IsNullOrWhiteSpace(displayName) || displayName.Length > 100 || memberLimit is < 1 or > 10000)) return new(400);
        if (selectedTenant is not null && (string.IsNullOrWhiteSpace(issuer) || issuer.Length > 2048 || issuer.Contains('\0')
            || string.IsNullOrWhiteSpace(subject) || subject.Length > 255 || subject.Contains('\0'))) return new(400);
        var prefix = Encoding.UTF8.GetBytes(operation + "\n" + selectedTenant?.ToString("D") + "\n");
        var digest = SHA256.HashData([.. prefix, .. body]);
        await using var connection = await database.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        NpgsqlCommand Command(string sql, params (string Name, object Value)[] values)
        {
            var command = new NpgsqlCommand(sql, connection, transaction);
            foreach (var (name, value) in values) command.Parameters.AddWithValue(name, value);
            return command;
        }
        Guid actorId;
        long grantVersion;
        bool quotaAvailable;
        await using (var grant = Command("""
            SELECT actor_id,version,allocated_tenants<tenant_limit FROM amdn_identity.platform_grants
            WHERE issuer=@issuer AND subject=@subject AND status='active' AND expires_at>clock_timestamp() FOR UPDATE
            """, ("issuer", actor.Issuer), ("subject", actor.Subject)))
        {
            await using var rows = await grant.ExecuteReaderAsync(ct);
            if (!await rows.ReadAsync(ct)) return new(403);
            (actorId, grantVersion, quotaAvailable) = (rows.GetGuid(0), rows.GetInt64(1), rows.GetBoolean(2));
        }
        await using (var current = Command("SELECT expires_at>clock_timestamp() FROM amdn_identity.platform_grants WHERE actor_id=@actor", ("actor", actorId)))
            if (await current.ExecuteScalarAsync(ct) is not true) return new(403);
        // The actor lock serializes concurrent replay/quota decisions and grant revocation.
        ProvisioningResult? replay = null;
        await using (var command = Command("""
            SELECT digest,tenant_id,user_id,postman_id FROM amdn_identity.provisioning_commands
            WHERE actor_id=@actor AND operation=@operation AND idempotency_key=@key
            """, ("actor", actorId), ("operation", operation), ("key", key)))
        {
            await using var rows = await command.ExecuteReaderAsync(ct);
            if (await rows.ReadAsync(ct))
            {
                if (!CryptographicOperations.FixedTimeEquals(rows.GetFieldValue<byte[]>(0), digest)) return new(409);
                replay = new(201, rows.GetGuid(1), rows.IsDBNull(2) ? null : rows.GetGuid(2), rows.IsDBNull(3) ? null : rows.GetGuid(3));
            }
        }
        var tenant = selectedTenant ?? replay?.TenantId;
        if (tenant is not null)
        {
            await using var gate = Command("""
                SELECT member_limit FROM amdn_identity.tenants
                WHERE tenant_id=@tenant AND provisioner_actor=@actor AND status='active' FOR UPDATE
                """, ("tenant", tenant.Value), ("actor", actorId));
            var limit = await gate.ExecuteScalarAsync(ct);
            if (limit is not int value) return new(404);
            memberLimit = value;
        }
        if (replay is not null)
        {
            if (replay.UserId is not null)
            {
                await using var active = Command("""
                    SELECT m.user_id FROM amdn_identity.memberships m JOIN amdn_identity.users u USING(tenant_id,user_id)
                      JOIN amdn_identity.postmen p ON p.tenant_id=m.tenant_id AND p.owner_user_id=m.user_id
                    WHERE m.tenant_id=@tenant AND m.user_id=@user AND m.status='active' AND u.status='active' AND p.status='active'
                    FOR SHARE OF m,u,p
                    """, ("tenant", replay.TenantId!.Value), ("user", replay.UserId.Value));
                if (await active.ExecuteScalarAsync(ct) is null) return new(403);
            }
            await transaction.CommitAsync(ct);
            return replay;
        }
        ProvisioningResult result;
        if (selectedTenant is null)
        {
            if (!quotaAvailable) return new(429);
            await using var create = Command("""
                INSERT INTO amdn_identity.tenants(display_name,member_limit,provisioner_actor) VALUES(@name,@limit,@actor) RETURNING tenant_id
                """, ("name", displayName!), ("limit", memberLimit), ("actor", actorId));
            tenant = (Guid)(await create.ExecuteScalarAsync(ct))!;
            await using var reserve = Command("UPDATE amdn_identity.platform_grants SET allocated_tenants=allocated_tenants+1 WHERE actor_id=@actor", ("actor", actorId));
            await reserve.ExecuteNonQueryAsync(ct);
            result = new(201, tenant);
        }
        else
        {
            await using var existing = Command("SELECT user_id FROM amdn_identity.memberships WHERE tenant_id=@tenant AND issuer=@issuer AND subject=@subject",
                ("tenant", selectedTenant.Value), ("issuer", issuer!), ("subject", subject!));
            if (await existing.ExecuteScalarAsync(ct) is null)
            {
                await using var count = Command("SELECT count(*) FROM amdn_identity.memberships WHERE tenant_id=@tenant", ("tenant", selectedTenant.Value));
                if ((long)(await count.ExecuteScalarAsync(ct))! >= memberLimit) return new(429);
            }
            PersonalPostman member;
            try { member = await IdentityProvisioner.EnsureMemberInTransaction(connection, transaction, selectedTenant.Value, issuer!, subject!, ct); }
            catch (InvalidOperationException) { return new(409); }
            result = new(201, member.TenantId, member.UserId, member.PostmanId);
        }
        await using var record = Command("""
            INSERT INTO amdn_identity.provisioning_commands(actor_id,operation,idempotency_key,digest,tenant_id,user_id,postman_id)
                VALUES(@actor,@operation,@key,@digest,@tenant,@user,@postman);
            INSERT INTO amdn_identity.provisioning_audit(actor_id,tenant_id,user_id,postman_id,action,grant_version)
                VALUES(@actor,@tenant,@user,@postman,@operation,@version)
            """, ("actor", actorId), ("operation", operation), ("key", key), ("digest", digest), ("tenant", result.TenantId!.Value), ("version", grantVersion));
        record.Parameters.Add(new NpgsqlParameter("user", NpgsqlDbType.Uuid) { Value = (object?)result.UserId ?? DBNull.Value });
        record.Parameters.Add(new NpgsqlParameter("postman", NpgsqlDbType.Uuid) { Value = (object?)result.PostmanId ?? DBNull.Value });
        await record.ExecuteNonQueryAsync(ct);
        await transaction.CommitAsync(ct); // Effect, quota, replay and audit are all durable before success.
        return result;
    }
}
