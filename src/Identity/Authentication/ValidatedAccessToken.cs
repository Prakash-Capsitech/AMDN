using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AMDN.Identity.Authentication;

// Immutable in-process evidence minted only by the successful OIDC validation event.
// It is not serialized into a cookie/token or constructible from request claims.
public sealed class ValidatedAccessToken
{
    internal const string Property = "AMDN.ValidatedAccessToken";
    public string Issuer { get; }
    public string Subject { get; }
    public string ClientId { get; }
    public string Scope { get; }
    public string? Acr { get; }
    public long? AuthTime { get; }
    public DateTime ExpiresAt { get; }

    internal ValidatedAccessToken(string issuer, string subject, string clientId, string scope, string? acr, long? authTime, DateTime expiresAt)
        => (Issuer, Subject, ClientId, Scope, Acr, AuthTime, ExpiresAt) = (issuer, subject, clientId, scope, acr, authTime, expiresAt);

    public static async Task<ValidatedAccessToken?> FromRequestAsync(HttpContext context)
    {
        // Ignore context.User: another middleware can replace/mutate that projection.
        var result = await context.AuthenticateAsync(IdentityAuthentication.Scheme);
        return result.Succeeded && result.Ticket?.AuthenticationScheme == IdentityAuthentication.Scheme
            ? result.Properties?.GetParameter<ValidatedAccessToken>(Property) : null;
    }
}
