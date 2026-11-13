# Provider-neutral API token authentication

F1.1 adds a resource-server authentication adapter using ASP.NET Core's JWT bearer
handler. It retrieves discovery metadata and public signing keys from one
configured HTTPS issuer. It issues no tokens, stores no private keys and requires
no provider client secret. Client login (authorization code with PKCE), provider
selection/rollout remain later F1 work. Membership resolution is covered by the
[identity persistence guide](identity-persistence.md).

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
- Optional `acr` must be a nonempty visible-ASCII string of at most 256 characters.
  Optional `auth_time` must be a nonnegative integer no later than `iat`. Duplicate
  top-level payload claim names, including unknown claims and equivalent
  JSON-escaped names, are rejected before principal projection.

These are strict token-profile rules even when device step-up is disabled:
malformed optional claims or duplicate claim names fail authentication. Missing
`acr` or `auth_time` does not invalidate an otherwise valid token for existing
APIs; the step-up policy separately requires both claims.

Unsigned tokens, symmetric algorithms, unexpected issuers/audiences, expired or
premature tokens and bearer headers over 16 KiB are rejected. Tokens are accepted
only from the Authorization bearer header; query parameters, tenant headers,
cookies and request bodies do not establish identity. Test tokens are generated
only in the test assembly with disposable in-memory keys.

After verification, the request principal retains only `iss`, `sub`, `client_id`
and optional `scope`, `acr` and `auth_time`. Provider role, tenant, user, postman, device and email claims
are discarded. The external `(issuer, subject)` is input to the verified
membership lookup; it is not an AMDN tenant/user identity. Scope also does not grant
object access. Client-credentials tokens may authenticate an external subject;
that does not make the subject an enrolled human or platform provisioner.

`AmdnTokenValidated` is an authentication-only policy for an explicit caller check.
It must not authorize data or commands. Default/fallback policies deny application
access even with a valid token, so a new mapped endpoint or bare
`RequireAuthorization()` cannot accidentally expose tenant data. F1.3 wires
current membership and operation-specific authorization into the opt-in owner API.
Without explicit API configuration, Gateway exposes only `/health/live` and a
public 404 fallback. Test probes are never deployed; see
[F1.3 configuration](provisioning-owner-access.md).

Failures return generic 401/403 Problem Details. A 401 includes `WWW-Authenticate:
Bearer`; no token, claim value or validation exception is returned. Validated
tokens are not saved in authentication properties. No request-body/token logging
or debug PII logging is enabled by this adapter.

## Device step-up prerequisite

F1.4 begins with the [E02 trust review](device-enrollment-review.md). An opt-in
`AmdnDeviceStepUpPrerequisite` policy checks recent authentication evidence from
the validated access token. It is **not enrollment authorization**: membership,
current object grants, device possession and messaging-key binding must still be
checked by the future operation. No production endpoint uses this policy yet;
enabling it does not enable the proposed
[enrollment/revocation commands](../protocols/device-enrollment.md).

`Authentication:DeviceStepUp` defaults disabled. Enabling requires enabled OIDC,
`AllowedAcrValues` (1–16 distinct, case-sensitive strings using the `acr` format
above) and `MaximumAgeSeconds` (1–900). Disabled settings require an empty list
and age zero. Partial or unknown configuration fails startup. Agree values with
the configured issuer; there is no universal `mfa` level, ACR ordering or
production default. Environment keys use `__` separators and numbered array
elements, such as `Authentication__DeviceStepUp__AllowedAcrValues__0`.

The policy requires exact `device.manage` scope, matching signed `acr`, and signed
`auth_time` between now minus the configured age and now, inclusive. It recomputes
freshness on every evaluation, adds no token-lifetime skew, and never substitutes
`iat`, `amr`, headers or query fields. Renewal does not renew authentication.
Insufficient evidence gives generic 403 on the test probe; malformed claims give
401. RFC 9470 interactive challenge/re-authentication is not implemented.

This follows the access-token evidence model in [RFC 9470 section 6](https://www.rfc-editor.org/rfc/rfc9470.html#section-6).
Provider rollout must verify each configured ACR's meaning and that `auth_time`
represents user authentication rather than token issuance. This code cannot
independently establish issuer assurance or recover a lost device.

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
Device step-up tests cover signed tokens over HTTP, exact age boundaries,
freshness after renewal, missing/wrong evidence, malformed and duplicate raw
claims, startup validation and continued denial of enrollment.

Production provider compatibility/rollout and login sessions remain pending.
See [identity persistence evidence](identity-persistence.md#evidence-and-remaining-work)
for membership coverage and its integration limits.
[Native N01/N02](agent-safety.md#pending-native-checks) and
[production P01–P03](../../tests/Harness/README.md#evidence-and-scope) stay pending.
F0 Proposed ADRs and A01–A07/E01–E06 reviews are not approved by these tests.

References: [ASP.NET Core JWT bearer validation](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-jwt-bearer-authentication?view=aspnetcore-10.0),
[RFC 9068 access-token profile](https://www.rfc-editor.org/rfc/rfc9068.html),
and [RFC 6750 bearer-token transport](https://www.rfc-editor.org/rfc/rfc6750.html).

The successful validation event also retains immutable in-process
`ValidatedAccessToken` evidence (no raw bearer token) for the
[enrollment principal mapper](enrollment-authority.md#principal-mapping).
Ordinary claim projection remains unchanged. This adds no login/token type or
enrollment endpoint; live enrollment, native and production checks remain pending.
