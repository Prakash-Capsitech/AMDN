# Identity

The first F1 slice implements [provider-neutral access-token validation](../../docs/security/oidc-authentication.md)
with explicit HTTPS issuer/audience configuration, public-key discovery, profile
checks and fail-closed authorization defaults. It does not resolve tenant membership,
provision identities, enroll devices or grant object access. See the
[F1 plan](../../docs/plan/f1.md) for remaining work and acceptance gates.
