using System.Security.Claims;
using AMDN.Identity.Authentication;

namespace AMDN.Identity.Membership;

public sealed record PersonalPostman(Guid TenantId, Guid UserId, Guid PostmanId,
    long IdentityVersion, long MembershipVersion, long PolicyVersion,
    bool ReceiveEnabled = true, bool DispatchEnabled = true, bool RetryEnabled = true);

public interface IPersonalPostmanStore
{
    // Tenant selection is a hint checked against current membership, never authority.
    Task<PersonalPostman?> ReadAsync(ClaimsPrincipal caller, Guid? selectedTenant = null, CancellationToken cancellationToken = default);
}

public sealed class VerifiedExternalSubject
{
    public string Issuer { get; }
    public string Subject { get; }
    private VerifiedExternalSubject(string issuer, string subject) => (Issuer, Subject) = (issuer, subject);

    public static VerifiedExternalSubject? FromPrincipal(ClaimsPrincipal principal)
    {
        var identities = principal.Identities.ToArray();
        if (identities.Length != 1 || !identities[0].IsAuthenticated
            || identities[0].AuthenticationType != IdentityAuthentication.Scheme) return null;
        var issuers = identities[0].FindAll("iss").ToArray();
        var subjects = identities[0].FindAll("sub").ToArray();
        if (issuers.Length != 1 || subjects.Length != 1 || !Valid(issuers[0].Value, 2048) || !Valid(subjects[0].Value, 255)) return null;
        return new VerifiedExternalSubject(issuers[0].Value, subjects[0].Value);
    }

    private static bool Valid(string value, int maximum) => !string.IsNullOrWhiteSpace(value)
        && value.Length <= maximum && !value.Contains('\0');
}
