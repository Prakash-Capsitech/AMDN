using System.Security.Claims;
using AMDN.Identity.Devices;
using AMDN.Identity.Membership;
using Npgsql;

namespace AMDN.Infrastructure.Identity;

// Not registered with Gateway. Does not verify possession or authorize device management.
public sealed class DeviceMetadataStore(NpgsqlDataSource runtimeDatabase) : IDeviceMetadataStore
{
    public async Task<DeviceMetadata?> ReadAsync(ClaimsPrincipal caller, Guid selectedTenant, Guid deviceId, CancellationToken cancellationToken = default)
    {
        var subject = VerifiedExternalSubject.FromPrincipal(caller);
        if (subject is null || selectedTenant == Guid.Empty || deviceId == Guid.Empty) return null;
        await using var connection = await runtimeDatabase.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        Guid user;
        await using (var resolve = new NpgsqlCommand("SELECT * FROM amdn_identity.resolve_membership(@issuer,@subject,@tenant)", connection, transaction))
        {
            resolve.Parameters.AddWithValue("issuer", subject.Issuer);
            resolve.Parameters.AddWithValue("subject", subject.Subject);
            resolve.Parameters.AddWithValue("tenant", selectedTenant);
            await using var rows = await resolve.ExecuteReaderAsync(cancellationToken);
            if (!await rows.ReadAsync(cancellationToken)) return null;
            if (rows.GetGuid(0) != selectedTenant) return null;
            user = rows.GetGuid(1);
            if (await rows.ReadAsync(cancellationToken)) return null;
        }
        await using (var context = new NpgsqlCommand("""
            SELECT set_config('amdn.tenant_id',@tenant,true),set_config('amdn.user_id',@user,true),
                   set_config('amdn.issuer',@issuer,true),set_config('amdn.subject',@subject,true)
            """, connection, transaction))
        {
            context.Parameters.AddWithValue("tenant", selectedTenant.ToString());
            context.Parameters.AddWithValue("user", user.ToString());
            context.Parameters.AddWithValue("issuer", subject.Issuer);
            context.Parameters.AddWithValue("subject", subject.Subject);
            await context.ExecuteNonQueryAsync(cancellationToken);
        }
        DeviceMetadata result;
        await using (var query = new NpgsqlCommand("""
            SELECT tenant_id,user_id,device_id,profile,status,record_version,created_at,updated_at,activated_at,revoked_at
            FROM amdn_identity.devices WHERE tenant_id=@tenant AND user_id=@user AND device_id=@device
            """, connection, transaction))
        {
            query.Parameters.AddWithValue("tenant", selectedTenant);
            query.Parameters.AddWithValue("user", user);
            query.Parameters.AddWithValue("device", deviceId);
            await using var rows = await query.ExecuteReaderAsync(cancellationToken);
            if (!await rows.ReadAsync(cancellationToken)) return null;
            result = new DeviceMetadata(rows.GetGuid(0), rows.GetGuid(1), rows.GetGuid(2), rows.GetString(3), rows.GetString(4),
                rows.GetInt64(5), rows.GetDateTime(6), rows.GetDateTime(7), rows.IsDBNull(8) ? null : rows.GetDateTime(8), rows.IsDBNull(9) ? null : rows.GetDateTime(9));
        }
        await transaction.CommitAsync(cancellationToken);
        return result;
    }
}
