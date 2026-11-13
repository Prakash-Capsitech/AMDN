# Staged device enrollment contract

Status: Proposed, OpenAPI `0.2.0-draft`. This specifies the next F1.4 implementation
boundary after the [credential design](../security/enrollment-credential-design.md).
No enrollment/revocation endpoint, device persistence, grant administration or
browser adapter is implemented. ADR 0011 remains Proposed. The former single-step
`POST /v1/devices`, `DeviceRequest` and `Device` schemas are removed from the draft;
Git history retains their blueprint provenance. There is no compatibility fallback.

## Commands and authority

Every command requires HTTPS, a valid OIDC access token, `tenant_id` query selector,
`Origin` and `Idempotency-Key`. Resolve the selector through the verified
issuer/subject's active membership; bodies cannot select an owner or postman.
Require the exact `device.manage` scope, fresh configured step-up and an explicit
current `device.manage` object grant, plus active tenant/user/membership/postman.
F1.3's `postman.read` grant supplies none of this new authority. Bind the verified
OIDC `client_id` too. Reauthorize retries and recheck authority/time after locks.

Require exactly one canonical HTTPS origin from deployment configuration and the
same origin throughout a ceremony, including raw signed client data. No wildcard,
`null`, cross-origin/top-origin, related-origin or forwarded-host fallback. The
Origin header is a binding input, not a substitute for signatures or account
authorization. Stored RP/origin configuration version must still be current.

All six commands return 200 JSON on success, whether newly committed or replayed.
No command returns 202 before commit. All responses, including errors, carry
`Cache-Control: no-store`. Exact shapes are in [OpenAPI](openapi.json).

| Operation | Request body schema | Successful result |
| --- | --- | --- |
| `POST /v1/device-enrollments` | `BeginEnrollment` | `EnrollmentRegistrationOptions` |
| `POST /v1/device-enrollments/{enrollmentId}/registration` | `WebAuthnRegistration` | `EnrollmentCandidateOptions` |
| `POST /v1/device-enrollments/{enrollmentId}/candidate-proof` | `WebAuthnAssertion` | Initial: `EnrollmentCompleted`; replacement: `EnrollmentCurrentOptions` |
| `POST /v1/device-enrollments/{enrollmentId}/current-proof` | `WebAuthnAssertion` | `EnrollmentCompleted` |
| `POST /v1/devices/{deviceId}/revocations` | `BeginRevocation` | `RevocationOptions` |
| `POST /v1/device-revocations/{revocationId}/proof` | `WebAuthnAssertion` | `RevocationCompleted` |

Begin enrollment fixes the profile, expected identity version and nullable
replacement device ID, then reserves a new server device UUID. Null replacement
is allowed only when no active device exists. After revocation, use the actual
current version, never reset it to zero. Replacement must name the current active
device and match its owner's version. Begin revocation binds the path device,
profile and expected version and must name the current active device. Versions
cannot overflow the JSON safe-integer range; exhaustion fails closed with 409.
One unfinished enrollment **or revocation** per tenant/user is allowed. A new
begin while one is pending conflicts; an exact valid begin replay is exempt.

Each proof binds the stored ceremony/operation/stage, owner, authenticated external
identity/client, origin/config version, expected identity version, replacement
reference and candidate UUID. Registration fixes the candidate credential ID and
verified COSE key. Its subsequent assertion must prove possession of that same
key. Only then can replacement issue a challenge to the old active credential.
The current-proof route is invalid for initial enrollment. Revocation challenges
are distinct from replacement challenges; no cross-operation proof reuse.

Successful registration and intermediate proofs atomically consume the challenge,
advance the stage, update credential counter/backup state and record replay/audit.
Activation additionally increments identity version, enforces one active device
and, for replacement, revokes the old credential in the same commit. Revocation
consumes its proof and atomically marks the device/credential revoked, increments
version and records replay/audit. No broker calls occur inside these transactions.
The [credential design](../security/enrollment-credential-design.md#validation-and-durable-effects)
owns verifier, RLS, uniqueness and lock/revalidation requirements.

## Browser projection and bounds

The AMDN request objects are deliberately smaller than WebAuthn's browser
`toJSON()` objects. The future client adapter copies `id`, `rawId`, `type` and
`clientExtensionResults`; registration copies only `clientDataJSON` and
`attestationObject` from `response`; assertion copies `clientDataJSON`,
`authenticatorData`, `signature` and optional `userHandle`. Encode raw ArrayBuffers
as canonical unpadded base64url. Do not parse and reserialize signed client data.
The browser's computed public key, publicKeyAlgorithm, authenticatorData for
registration, transports and authenticatorAttachment are omitted, not accepted
as alternative authorities. The server obtains the key from verified attestation.
This is a projection of the [standard JSON serialization](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#dom-publickeycredential-tojson),
not a claim that unmodified browser `toJSON()` output matches these schemas.

The adapter must reject nonempty extension results before projecting; it must not
strip an unexpected extension to fabricate `{}`. The server must also reject
unexpected authenticator extension data. `id` and `rawId` must match one another
and the verified/stored credential ID. Assertion userHandle may be absent or null
only for the identified owner and exact single allowed credential; a supplied
value must match the stored 32-byte handle. These are semantic checks, not JSON
Schema equality checks.

The returned `public_key` is a JSON representation of the browser's `publicKey`
options: decode challenge, user.id and credential descriptor IDs before calling
`create`/`get` (or use the browser's standard options parser). User labels must be
opaque/pseudonymous, never an email or raw OIDC subject. Creation offers only
ES256, `attestation: none`, discouraged residency and required UV. Its exclusion
list contains the current credential if any; database uniqueness still covers
all pending/active/retained revoked credentials, including omitted older ones.
Assertions have exactly one allowed stored credential and required UV. No
extensions, custom signing transcript or message keys are negotiated.

| Field | Decoded maximum | Encoded maximum characters |
| --- | --- | --- |
| credential ID (`id`, `rawId`, descriptors) | 1,023 bytes | 1,364 |
| clientDataJSON | 8,192 bytes | 10,923 |
| attestationObject | 16,384 bytes | 21,846 |
| authenticatorData | 4,096 bytes | 5,462 |
| signature | 1,024 bytes | 1,366 |
| challenge / supplied userHandle / user.id | Exactly 32 bytes | Exactly 43 |

The complete uncompressed UTF-8 command body is limited to 65,536 bytes, before
parsing. Reject duplicate JSON names (including escaped equivalents), unknown
fields, invalid UTF-8, compression, noncanonical base64url and oversized decoded
fields. A schema-valid byte string is not valid CBOR, client data or cryptography.
Strict parsing, exact origin/RP, none attestation, UP/UV, signature, algorithm,
BE/BS, counter and stored-context checks all remain implementation obligations.
The examples under [examples/enrollment](examples/enrollment/BeginEnrollment.json)
contain synthetic shape-only bytes, not reusable production proofs or credentials.

## Expiry, failures and replay

The [state graph](enrollment-state-machine.json) distinguishes initial enrollment,
replacement and revocation. A ceremony expires five minutes after begin; each
challenge expires two minutes after issuance, capped by ceremony expiry. Browser
`timeout: 120000` is only a hint. Expiry of the current challenge terminates the
whole ceremony; there is no refresh/resurrection operation. Completed ceremonies
do not expire into a different result. Expired/abandoned candidates never replace
an active device; a fresh begin requires a new key and credential. No cancellation,
lost-credential recovery or bearer-only emergency revocation is introduced.

Before expensive verification, durably reserve an attempt under its stage/key and
request digest. At most five attempts may be reserved per stage, including crashed
or interrupted verification. A successful fifth attempt can advance; a fifth
failed attempt abandons. An unresolved reservation consumes capacity and cannot
be rerun as a fresh attempt; return 503 until reconciled, or expire the ceremony.
Persist a failed verification's generic 400 outcome for exact retry. Replaying
that failure consumes no additional attempt and cannot become success. Parse,
authentication and budget failures before verification do not reserve attempts
but still count against configured request-rate budgets. No side effects from a
failed proof, except its attempt/outcome and minimal audit, are committed.

Replay keys are scoped by authenticated tenant/local user, operation, target
ceremony and stage. Begin uses operation plus target (replacement/null or revoked
device) before a ceremony UUID exists. Hash the exact UTF-8 body and bind the
path/query target, verified issuer/subject/client_id and initiating origin. A key
cannot cross actors, stages or operations. Same key with different bytes or
binding conflicts; changing JSON whitespace is a different request. Another key
for an already consumed challenge conflicts even if its bytes are identical.

An exact successful intermediate-stage replay returns the original options only
while the returned challenge is still current, unconsumed and unexpired, and the
bound lifecycle/version context still holds. Otherwise return 409, without old
options or a new challenge. This includes a begin replay after registration has
advanced. Clients retain the latest successful stage request/key to recover a
lost response. Replaying a successfully completed candidate/current/revocation
proof returns its historical completion result plus a **fresh** `current_lifecycle`
snapshot after current authority checks. It never reruns effects. Historical
`committed_identity_version` and `completed_at` do not change; snapshot version
may be newer, and an enrolled device may now be `revoked`. Snapshot version must
be at least the committed version. Device status and version must be read
consistently. A replay is an observation, not a promise against later revocation.

| Status / code | Enrollment-specific meaning |
| --- | --- |
| 400 / invalid_request | Malformed fields/encoding, duplicate names, mismatched IDs or generic failed proof; do not reveal verifier details |
| 401 / unauthenticated | Missing/invalid token; WWW-Authenticate required |
| 403 / forbidden | Missing scope, grant, fresh step-up or permitted origin |
| 404 / not_found | Missing or inaccessible tenant/ceremony/device, indistinguishable |
| 409 / conflict | Wrong stage, stale version/config, expired/abandoned ceremony, credential reuse, active/pending conflict, changed replay bytes or consumed challenge |
| 413 / payload_too_large | Whole-body or encoded/decoded field limit |
| 415 / unsupported_media_type | Non-JSON media type or compressed body |
| 429 / rate_limited | Configured request/capacity budget; Retry-After required |
| 503 / unavailable | Transient storage/verifier availability or unresolved reservation; Retry-After required; no implied commit |

Authorization/visibility checks precede replay disclosure and conflict detail.
A fifth failed proof returns its generic 400; later new attempts see terminal
409. Retried recorded failures remain generic 400 after authorization, even when
the ceremony is abandoned. Expiry/context changes are checked before a *new*
proof effect, including after lock waits. A stale bound context abandons a pending
ceremony; lack of authority still returns 403/404 without exposing its state.
Automatic replay/tombstone cleanup remains disabled pending A06 retention review.
Errors and logs must not contain tokens, raw proofs, private keys or hidden owners.

## Evidence boundary and next implementation

`make contracts-test` validates OpenAPI, all synthetic examples, encoding bounds,
closed object shapes, proof-stage response alternatives and terminal transition
paths. These are tests of the declared contract, not a running enrollment service.
The separate [verifier experiment](../../experiments/Enrollment/README.md) tests
synthetic cryptographic inputs; neither suite proves browser UX, database replay,
RLS, concurrent replacement or actual grant enforcement.

Next implement the scoped device persistence/transaction boundary, explicit grant
administration and opt-in API adapter with real HTTP/role/pool negative and race
tests. Enrollment can only create `credential_active` with `messaging_ready: false`
and no `key_id`. Message-key binding and device execution credentials remain
separate designs; independently verify peer keys before any first send and after
replacement. E01/E02/E06, F0 review gates, [native N01/N02](../security/agent-safety.md#pending-native-checks)
and full [production P01–P03](../../tests/Harness/README.md#evidence-and-scope)
remain pending. Dependabot #10 stays deferred; no security gate or dependency pin
is changed here.
