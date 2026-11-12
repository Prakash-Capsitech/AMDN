# Provider-neutral API token authentication

F1.1 adds a resource-server authentication adapter using ASP.NET Core's JWT bearer
handler. It retrieves discovery metadata and public signing keys from one
configured HTTPS issuer. It issues no tokens, stores no private keys and requires
no provider client secret. Client login (authorization code with PKCE), provider
selection/rollout and tenant membership remain later F1 work.

## Configuration

The Gateway starts with authentication disabled when this section is absent.
Explicit `Enabled: false` also disables validation when issuer and audience are
omitted or empty. Health remains public and unimplemented routes return 404.
Enabling the adapter requires all three values below. Partial enabled configuration,
nonempty issuer/audience values while disabled, and malformed or unknown settings
fail startup.
These are configuration examples, not usable credentials:

```json
{
  "Authentication": {
    "Oidc": {
      "Enabled": true,
      "Issuer": "https://identity.example.invalid/realms/amdn",
      "Audience": "amdn-api"
    }
  }
}
```

Equivalent environment variables are `Authentication__Oidc__Enabled`,
`Authentication__Oidc__Issuer` and `Authentication__Oidc__Audience`. The issuer is
an exact, case-sensitive token issuer string and must use HTTPS without userinfo,
query or fragment. Discovery is `<issuer-without-trailing-slash>/.well-known/openid-configuration`.
The advertised discovery issuer must equal the configured issuer. The audience
must be a dedicated API resource audience, not the interactive client's ID.
Trailing slashes are significant for audience matching too.

There is no HTTP metadata switch, certificate-validation bypass, arbitrary
metadata URL, uploaded signing key or shared-secret token mode in application
configuration. Discovery redirects are refused; configure the canonical issuer.
The standard library caches and refreshes signing keys, including refresh after
an unknown key ID. Backchannel requests time out after five seconds. A cold
instance cannot authenticate when discovery fails. Cached keys can continue to
validate otherwise-valid tokens during an outage; token authentication is not
immediate revocation or a membership lookup.

Use HTTPS for deployed API traffic, directly or through a reviewed TLS-terminating
proxy. Proxy trust, hosting and production identity-provider configuration remain
pending; this change does not install a deployment or configure forwarded headers.

## Accepted token profile

The first adapter supports the RFC 9068 JWT access-token profile, not every
vendor-specific OIDC token format. The provider must issue API access tokens with:

- A valid asymmetric signature using RS256 and an issuer-published key.
- `typ` equal to `at+jwt` or `application/at+jwt`. OIDC ID tokens and generic
  `JWT` tokens are rejected even if their signature and audience otherwise match.
- A string `iss` matching the configured issuer exactly. `aud` must be a string
  or a nonempty array containing only strings, with at least one exact match for
  the configured audience. Null or non-string array elements fail even alongside
  a matching audience.
- Required integer `exp`, valid integer `nbf` if present, and a 30-second clock
  skew allowance for lifetime validation.
- Single nonempty strings for `sub`, `client_id` and `jti`, plus integer `iat`
  no later than the skew allowance and earlier than expiry. Missing or ambiguous
  subject claims fail.
- If present, a single space-delimited OAuth `scope` string with valid scope tokens.

Unsigned tokens, symmetric algorithms, unexpected issuers/audiences, expired or
premature tokens and bearer headers over 16 KiB are rejected. Tokens are accepted
only from the Authorization bearer header; query parameters, tenant headers,
cookies and request bodies do not establish identity. Test tokens are generated
only in the test assembly with disposable in-memory keys.

After verification, the request principal retains only `iss`, `sub`, `client_id`
and optional `scope`. Provider role, tenant, user, postman, device and email claims
are discarded. The external `(issuer, subject)` is input to a future verified
membership lookup; it is not an AMDN tenant/user identity. Scope also does not grant
object access. Client-credentials tokens may authenticate an external subject;
that does not make the subject an enrolled human or platform provisioner.

`AmdnTokenValidated` is an authentication-only policy for an explicit caller check.
It must not authorize data or commands. Default/fallback policies deny application
access even with a valid token, so a new mapped endpoint or bare
`RequireAuthorization()` cannot accidentally expose tenant data. F1.2/F1.3 must
add current membership and operation-specific authorization. The Gateway exposes
only `/health/live` and a public 404 fallback; no test probe or identity API is shipped.

Failures return generic 401/403 Problem Details. A 401 includes `WWW-Authenticate:
Bearer`; no token, claim value or validation exception is returned. Validated
tokens are not saved in authentication properties. No request-body/token logging
or debug PII logging is enabled by this adapter.

## Evidence and remaining gates

Run `dotnet test tests/Integration/AMDN.Integration.Tests.csproj -c Release` or
`make verify`. Tests host the actual Gateway on loopback Kestrel, add routes only
from the test assembly, and use a real local HTTPS discovery/JWKS server. The
fixture pins only its own ephemeral certificate in its own test backchannel;
production TLS settings have no bypass. This is real HTTP, signing and validation,
not a fake authentication handler. Keys/certificates are never written to files.

Coverage includes valid signatures and claim filtering, missing/invalid tokens,
wrong issuer/audience, time bounds, ID-token confusion, unsigned/symmetric tokens,
missing or incorrectly typed profile claims, configuration errors, untrusted TLS, unavailable discovery,
metadata issuer mismatch, key rollover, header/query spoofing and default-deny
application access. The separate PostgreSQL/JetStream harness remains required.

Production provider compatibility/rollout, login sessions, current membership and
device revocation, application SQL roles/pooling and worker integration are pending.
[Native N01/N02](agent-safety.md#pending-native-checks) and
[production P01–P03](../../tests/Harness/README.md#evidence-and-scope) stay pending.
F0 Proposed ADRs and A01–A07/E01–E06 reviews are not approved by these tests.

References: [ASP.NET Core JWT bearer validation](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-jwt-bearer-authentication?view=aspnetcore-10.0),
[RFC 9068 access-token profile](https://www.rfc-editor.org/rfc/rfc9068.html),
and [RFC 6750 bearer-token transport](https://www.rfc-editor.org/rfc/rfc6750.html).
