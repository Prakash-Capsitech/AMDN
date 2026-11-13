# ADR 0011 WebAuthn enrollment credentials

Status: Proposed
Date: 2026-11-12
Decision owner: AMDN maintainer and identity/security reviewers
Source: F1.4 and E02; maintainer's logical-device and independent-verification choices

## Context

The existing device JSON has no possession ceremony. OIDC step-up establishes
recent account authentication, but neither a public-key upload nor a bearer token
proves possession of a device credential. AMDN must not invent a crypto protocol
or silently select the experimental MLS implementation for production.

## Proposed decision

Select **WebAuthn registration followed by assertion**, using ES256, required user
presence/verification and none attestation, as the F1.4 enrollment credential
design. Evaluate the pinned Fido2 4.3.3 verifier used by the isolated experiment
for the application adapter. Keep OIDC login and current AMDN membership/grants
as additional requirements. Permit backup-eligible credentials under the selected
one-active-logical-device guarantee; make no hardware or non-copyability claim.

Use a stored, expiring, single-use ceremony; activation requires a signature by
the candidate credential. Normal replacement additionally requires a signature
from the current credential bound to that candidate. Lost-credential recovery
has no self-service fallback in this design. A separately reviewed recovery
operation is required before one can be offered.

Keep the WebAuthn credential separate from messaging keys. Credential enrollment
does not publish a messaging key, enable delivery or approve an encryption
profile. The [detailed design](../security/enrollment-credential-design.md) defines
the staged states, ceremony, replacement, revocation and enforcement boundaries.
It supersedes the old single-request `DeviceRequest` design for implementation.

## Alternatives

DPoP is useful for sender-constrained API tokens but requires authorization-server
support and does not prove possession of an unrelated messaging key or user
verification. Bare MLS package upload does not authenticate an AMDN owner.
ASP.NET Identity passkeys would introduce another account-store framework into
the existing OIDC/membership model. Hardware attestation imposes a different
supported-device and trust-root policy than the chosen logical-device guarantee.
Custom signature challenges are rejected by ADR 0007.

## Consequences and evidence

The [isolated experiment](../../experiments/Enrollment/README.md) exercises the
actual pinned verifier with synthetic fixtures and documents the application
checks it does not supply. It is not a browser trial or independent audit.
Replacement may require a second authenticator if the platform cannot retain
both credentials through the ceremony. Synced credentials may exist on several
physical devices; neither counters nor one active database row prove otherwise.

This resolves the engineering direction, not E02 production acceptance.
See the [verifier guide](../security/enrollment-verifier.md) for internal
proof/persistence integration and its evidence boundary. Authenticated HTTP/client
integration, independent crypto review,
messaging-key binding, client-distribution trust, native N01/N02 and production
P01–P03 remain pending. Record named reviewer, date and evidence before changing
this ADR's status. Approval: not recorded.
