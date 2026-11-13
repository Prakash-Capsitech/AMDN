using System.Text;
using AMDN.Identity.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace AMDN.Enrollment;

// Explicit deployment binding. Never derive from Host, forwarded headers or body fields.
public sealed class EnrollmentConfiguration
{
    public Guid Id { get; }
    public string Origin { get; }
    public EnrollmentConfiguration(Guid id, string origin)
    {
        if (id == Guid.Empty || !Uri.TryCreate(origin, UriKind.Absolute, out var uri) || uri.Scheme != "https"
            || uri.GetLeftPart(UriPartial.Authority) != origin || uri.UserInfo.Length != 0 || origin.Length > 512)
            throw new ArgumentException("Enrollment requires an explicit configuration ID and canonical HTTPS origin.");
        (Id, Origin) = (id, origin);
    }
}

// A validated external actor plus a tenant selection FILTER. SQL must still resolve
// current membership and grants before every command. This is not a durable grant.
public sealed class EnrollmentPrincipal
{
    internal CeremonyActor Actor { get; }
    internal EnrollmentPrincipal(CeremonyActor actor) => Actor = actor;
}

public sealed class EnrollmentPrincipalMapper(EnrollmentConfiguration configuration,
    IOptions<DeviceStepUpSettings> stepUp, TimeProvider clock)
{
    public async Task<EnrollmentPrincipal?> FromRequestAsync(HttpContext context, Guid selectedTenant)
    {
        var token = await ValidatedAccessToken.FromRequestAsync(context);
        var policy = stepUp.Value;
        var now = clock.GetUtcNow();
        if (token is null || selectedTenant == Guid.Empty || !policy.Enabled
            || policy.MaximumAgeSeconds is < 1 or > 900 || token.ExpiresAt <= now.UtcDateTime
            || !token.Scope.Split(' ').Contains("device.manage", StringComparer.Ordinal)
            || token.Acr is null || !policy.AllowedAcrValues.Contains(token.Acr, StringComparer.Ordinal)
            || token.AuthTime is not { } authTime || authTime < 0 || authTime > now.ToUnixTimeSeconds()
            || now.ToUnixTimeSeconds() - authTime >= policy.MaximumAgeSeconds
            || !Bounded(token.Issuer, 2048) || !Bounded(token.Subject, 255) || !Bounded(token.ClientId, 256)) return null;
        var authenticatedAt = DateTimeOffset.FromUnixTimeSeconds(authTime).UtcDateTime;
        var stepUpDeadline = authenticatedAt.AddSeconds(policy.MaximumAgeSeconds);
        var authorityDeadline = token.ExpiresAt < stepUpDeadline ? token.ExpiresAt : stepUpDeadline;
        return new EnrollmentPrincipal(new CeremonyActor(selectedTenant, token.Issuer, token.Subject, token.ClientId,
            configuration.Origin, configuration.Id, token.Scope, token.Acr, authenticatedAt, authorityDeadline));
    }
    private static bool Bounded(string value, int max) => !string.IsNullOrWhiteSpace(value) && !value.Contains('\0') && Encoding.UTF8.GetByteCount(value) <= max;
}
