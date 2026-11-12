using System.Security.Claims;

namespace AMDN.Identity.Membership;

public static class IdentityScopes
{
    public static bool Has(ClaimsPrincipal principal, string required)
    {
        if (VerifiedExternalSubject.FromPrincipal(principal) is null) return false;
        var scopes = principal.FindAll("scope").ToArray();
        return scopes.Length == 1 && scopes[0].Value.Split(' ').Contains(required, StringComparer.Ordinal);
    }
}
