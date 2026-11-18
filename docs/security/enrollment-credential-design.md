# F1.4 enrollment credential design

Status: Engineering design selected for the next implementation slice,
12 November 2026. [ADR 0011](../adr/0011-webauthn-enrollment-credentials.md) remains
Proposed; independent approval and E02 closure are **not** recorded. This document
specifies intended ceremony behavior, not deployed enrollment endpoints. The
[storage foundation](device-persistence.md) now defines retained device records and
metadata reads. [Internal ceremony transactions](ceremony-transactions.md) now
record trusted verifier projections. The [isolated verifier bridge](enrollment-verifier.md)
now connects cryptographic verification to those transactions; the [principal/role bridge](enrollment-authority.md)
supplies signed-token and scoped-role integration. See the [HTTP guide](enrollment-http.md)
for adapter configuration and evidence limits.

## Credential and authority

Use WebAuthn for an interactive AMDN enrollment credential. OIDC remains the
account login; WebAuthn supplies additional possession/user-verification evidence.
Use a separate random credential for each logical device enrollment, with one
active logical device per tenant/user. Backup-eligible/synced credentials are
allowed: this is not physical-device binding. Do not infer assurance from AAGUID,
transports, a signature counter or an unverified authenticator label.

The selected profile is `amdn-webauthn-enrollment/1`. Parameters:

| Item | Design choice |
| --- | --- |
| Standard | WebAuthn Level 3 registration and authentication verification procedures |
| Key algorithm | Only COSE ES256 (-7), EC2 P-256; no algorithm negotiation beyond this list |
| Attestation | Request and accept `none` only; no hardware trust or MDS fetching |
| Presence / verification | Require UP and UV at registration and every assertion |
| RP and origin | Explicit deployment RP ID and canonical HTTPS origin allowlist; no wildcard, forwarded-host derivation, cross-origin or related-origin fallback |
| Discoverability | `residentKey: discouraged`; account selected through OIDC; exact `allowCredentials` on assertions; no usernameless login |
| User handle | Random 32-byte opaque value per tenant/user, stable within that RP; not an email, OIDC subject or authorization token |
| Challenge | Fresh 32 cryptographically random bytes per stage, stored server-side; browser timeout 120 seconds is a hint only |
| Expiry | Entire ceremony expires 5 minutes after creation; every issued stage challenge also expires after 2 minutes, capped by ceremony expiry |
| Initial verifier | Fido2 4.3.3, pinned in the experiment and verifier library |

These are AMDN profile restrictions. The [WebAuthn verification procedures](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-rp-operations)
remain authoritative for the standard checks. Do not implement a local signature,
COSE or attestation verifier from this prose or copy the synthetic test generator
into application code. Unsupported authenticators fail clearly; no weaker fallback.
The first client adapter targets first-party browser WebAuthn `create`/`get`
with this profile. Chrome, Firefox, Safari and mobile versions still need actual
qualification; the synthetic experiment qualifies no browser or authenticator.
Native clients and embedded/cross-origin ceremonies are outside this first profile.

Credential operations require the validated OIDC issuer/subject, exact
`device.manage` scope, current active tenant/user/membership/postman, fresh
[step-up evidence](oidc-authentication.md#device-step-up-prerequisite) and an
explicit unexpired `device.manage` object grant. F1.3 only provisions
`postman.read`; it must not acquire device authority implicitly.
[Audited grant administration](enrollment-administration.md) is a prerequisite to
enabling the API. The credential cannot authenticate another tenant's membership.

## Separation from messaging

The WebAuthn key is an enrollment/management authentication key. It is never an
MLS signing key, encryption key, provider recovery key or general signing oracle.
It does not authorize background acknowledgments or mint a new token type.
Device-bound execution credentials for later delivery operations require their
own reviewed integration; an ordinary OIDC token still supplies no device proof.

Enrollment creates a `credential_active` logical identity with
`messaging_ready: false` and no `key_id`. Directory publication, message admission,
delivery and device acknowledgments must reject it until a separately reviewed
messaging profile binds and validates the required keys. Do not store opaque
unvalidated key packages as active keys. The earlier single-step draft combining
`public_key_package` and `DeviceRequest` is superseded; it is not implementable as
an alternate route. A later messaging-binding design must specify protocol key
validation, proof of required private-key possession, immutable binding to this
device/version and atomic readiness activation. That remains E02-D4/E01 work.

Peer trust is a further, client-side condition: independently verify the complete
peer identity/key binding before **any** first send and after replacement. No
server enrollment result or `messaging_ready` state establishes that peer trust.
The fingerprint/comparison format and trusted client distribution remain open.

## Ceremony and proposed HTTP responsibilities

The [versioned HTTP contract](../protocols/device-enrollment.md) owns the staged
commands, browser projection, transport requirements, errors and replay rules;
[OpenAPI](../protocols/openapi.json) owns their exact request/response schemas.
The [HTTP guide](enrollment-http.md#evidence-and-remaining-work) owns adapter
integration evidence and remaining qualification work.

Bind every stage to ceremony UUID, operation/stage, tenant, local user, verified
issuer/subject, OIDC `client_id`, exact initiating origin, RP/origin configuration version, expected
identity version, replacement target, candidate device UUID and (once known)
exact credential ID/public key. Use the stored options/context, never options
echoed by the client. Signed challenge bytes select this immutable context;
there is no custom signed JSON or new cryptographic transcript format.

Only one candidate can be attached to an intent. Registration retry with different
bytes conflicts; changing the candidate requires a fresh ceremony. Replacement's
old-credential challenge is issued only after the candidate is fixed and proves
possession, so old authorization cannot be transplanted to another candidate.
Require a fresh distinct candidate ID/key; reject reuse of current or retained
revoked credentials. Authenticator exclusion lists are a UX aid, not the
database uniqueness boundary.

An active device can be replaced only by an intent that explicitly names it and
matches the current version. Initial enrollment cannot run when an active device
exists. After revocation, enrollment still requires the current version/grant
and fresh step-up; terminal revoked rows and old keys are never resurrected.
For normal replacement the user must retain access to the old credential until
completion. A platform unable to hold both may require another authenticator.
If the current credential is lost, ordinary self-service replacement/revocation
fails closed. Emergency administrative revocation and recovery need a separately
reviewed, audited policy; no email reset, bearer-only override or provider
decryption key is introduced here.

## Validation and durable effects

Fido2 validates the standard signature/ceremony inputs. The application adapter
must additionally enforce limits before parsing: 64 KiB complete JSON request,
8 KiB decoded client data, 16 KiB decoded attestation object, 4 KiB decoded
authenticator data, 1 KiB signature and 1,023-byte credential ID. Reject duplicate
JSON fields, noncanonical base64url, unknown AMDN fields, unexpected WebAuthn
extensions, formats other than none and unexpected COSE algorithms. Use bounded
parsers; no attacker-controlled URLs, attestation certificate chains or metadata
fetches. These limits require negative/fuzz tests, not assumptions about library
defaults. Reject cross-origin/top-origin use; do not accept AppID fallback.

Verify the request's exact configured origin and RP in addition to library
configuration normalization. Untrusted Host/forwarded headers cannot choose
either. Standard client-data checks still use the signed raw client-data hash.
Credential ID must match the stored candidate/current record and allowed list;
if userHandle is present it must equal the stored handle. Absence is permitted
only for the already identified owner and explicit allowed credential; it must
never skip ownership checks. Deny unknown or revoked credentials before effects.

The [device storage guide](device-persistence.md#records-and-constraints) owns
retained credential bindings, normalized public-key storage, uniqueness and
BE/BS/counter constraints. Proof verification adds stricter counter rules:
for nonzero counters, non-increase/reset fails closed; zero-to-zero is allowed
and proves no clone resistance. Serialize counter changes with credential use.
The experiment shows that Fido2 does not consume challenges or compare BE with
stored registration; these checks belong to the application transaction.

This ceremony does not eliminate bearer-token theft: a stolen token already
carrying a fresh accepted ACR and enrollment grant can satisfy the initial
account-authentication prerequisite. WebAuthn possession is not proof that the
OIDC token was obtained by its rightful owner. Provider assurance, token custody,
client/session protections and any future sender constraints require deployment
review; do not advertise the design as solving that residual risk. Replacement's
current-credential proof adds a separate condition absent from first enrollment.

Each successful stage atomically consumes its challenge, records a replay result
and audit, and advances state. Final activation additionally locks current
membership/user/grant/device records in a fixed documented order, rechecks all
lifecycle versions, authorization and time limits **after lock waits**, increments
identity version, enforces the unique active-device constraint, and commits any
replacement/revocation together. Verification outside the transaction is only a
precheck; reload/compare the exact verified state before effects. No provider or
broker call belongs inside the database transaction.
Replacement does not transfer old message keys, sessions or deliveries to the
candidate. Their original device/key attribution remains; the new device stays
unavailable for messaging until a new reviewed binding and peer verification.

The [expiry, failure and replay contract](../protocols/device-enrollment.md#expiry-failures-and-replay)
owns replay scoping, intermediate/completed replay eligibility and durable
verification reservations, including interrupted attempts. Rollback of stage
effects leaves no consumed proof or partial identity; it does not erase an
independently committed attempt reservation.

Pending ceremonies expire without changing active identity; device storage rows
have no automatic expiry. Cleanup may delete expired proof bytes, but retains
audit/replay/tombstone attribution for the reviewed retention window; automatic
cleanup remains disabled until A06 sets it.
Audit only actor/resource IDs, operation, version and outcome. Never log tokens,
raw WebAuthn responses, private keys, key packages or plaintext. Migration and
runtime roles stay separate; add narrow reviewed device functions/role authority,
not general writes for Gateway's existing read-only pool.

## Evidence and remaining gates

The [31-case verifier experiment](../../experiments/Enrollment/README.md) establishes
synthetic ES256 compatibility and negative validation on the pinned library. It
does not establish browser interoperability, durable replay/expiry/quotas,
replacement races, RLS, real OIDC assurance, grants or client UX. Those must be
tested through actual APIs, pooled roles and supported browsers in subsequent
slices. Include wrong owner/tenant, state/version changes during waits, stale
proofs, interrupted responses, audit failure and parallel ceremonies.

Credential choice and ceremony responsibilities are specified here. E02-D1
implementation/security acceptance, E02-D2 verification UX, E02-D3 distribution,
E02-D4 messaging binding, E01/E06 independent review, native N01/N02 and full
production P01–P03 remain pending. Dependabot #10 was separately evaluated and
closed without merging; see the
[compatibility evaluation](../../clients/crypto/README.md#pr-10-compatibility-evaluation).
No sandbox, hook, PR or CI gate is weakened by this design or experiment.
