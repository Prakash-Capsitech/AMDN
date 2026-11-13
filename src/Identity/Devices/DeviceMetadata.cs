using System.Security.Claims;

namespace AMDN.Identity.Devices;

// Storage metadata, not an enrollment result, messaging credential or authorization grant.
public sealed record DeviceMetadata(Guid TenantId, Guid UserId, Guid DeviceId, string Profile,
    string Status, long RecordVersion, DateTime CreatedAt, DateTime UpdatedAt,
    DateTime? ActivatedAt, DateTime? RevokedAt);

public interface IDeviceMetadataStore
{
    // Internal membership-scoped read. A future endpoint additionally needs its operation policy.
    Task<DeviceMetadata?> ReadAsync(ClaimsPrincipal caller, Guid selectedTenant, Guid deviceId, CancellationToken cancellationToken = default);
}
