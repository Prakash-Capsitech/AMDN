# Opt-in enrollment and revocation HTTP

Gateway registers the six [staged commands](../protocols/device-enrollment.md)
only when `EnrollmentApi:Enabled` is explicitly true. The default host exposes
none of them. This is a synthetic integration boundary, not production enrollment
approval or messaging-key activation. The [browser adapter](../../clients/web/README.md)
is a separate first-party module with virtual-authenticator evidence.

## Configuration and deployment

Apply roles and migrations 001–007 explicitly with the migration runner. Do not
run migrations at application startup. Use the
[audited administrator commands](enrollment-administration.md) to create an enabled
RP configuration and a finite management grant. Give Gateway a distinct login
inheriting only `amdn_identity_enrollment`, with no SET membership in its executor
or owner. The HTTP integration owns a separate guarded pool and does not reuse
the owner-read `IdentityApi` pool or its authority.

Configure these settings through the deployment's protected configuration source:

| Setting | Required value when enabled |
| --- | --- |
| Authentication:Oidc | Enabled, explicit issuer and audience; existing JWT validation rules apply |
| Authentication:DeviceStepUp | Enabled, explicit allowed ACRs and maximum age |
| EnrollmentApi:Enabled | true |
| EnrollmentApi:ConnectionString | Dedicated enrollment login; never migration/provisioning/runtime login |
| EnrollmentApi:ConfigurationId | Nonzero UUID of the administrator-created configuration |
| EnrollmentApi:Origin | Exact canonical HTTPS DNS origin, no path, explicit default port or numeric terminal DNS label |
| EnrollmentApi:MaximumPoolSize | 1–20 |
| EnrollmentApi:RequestsPerMinute | 1–10000, process-wide |
| EnrollmentApi:ActorRequestsPerMinute | 1 through the process-wide limit |
| EnrollmentApi:TenantRequestsPerMinute | 1 through the process-wide limit |
| EnrollmentApi:MaximumConcurrentProofs | 1–32, no queue |

All enrollment settings must be empty/zero when disabled. Inconsistent or unknown
settings fail startup. Configuration is a process-lifetime binding; restart after
deployment changes. No login, password, production issuer or RP is installed by
this feature. Deployment TLS termination/forwarding must preserve the trusted
HTTPS boundary; arbitrary forwarded headers do not establish it.

## Authority, transport and transactions

Every mapped command requires HTTPS, one canonical lowercase UUID `tenant_id`
query parameter with no other query keys, exactly the configured Origin and one
visible-ASCII Idempotency-Key of 16–128 characters. The route UUID is canonical too.
The immutable validated token supplies issuer, subject, client, exact device.manage
scope and fresh step-up. Mutable claims and tenant/forwarded headers supply no
authority. No CORS wildcard, cookie authorization or Origin fallback is provided.

Migration 007 adds the execute-only `amdn_enrollment.authorize` entry. It resolves
current membership and checks grants/configuration under the existing lock order
in its own transaction. Only a successful check permits charging a tenant budget.
The check commits before body processing and is never a cached mutation grant:
begin, reserve, finish and fail independently reauthorize under their own locks,
including after waits. Application table/helper access remains denied and RLS
context remains transaction-local.

Process-wide and verified issuer/subject budgets include failed requests before
endpoint authorization; anonymous requests consume the process-wide budget.
Changing client_id does not reset an actor budget. Unauthorized tenant selections
cannot charge the selected tenant. Proof verification also requires a separate
concurrency permit. These are local fixed-window budgets, not distributed quotas;
multiple Gateway replicas need a separately reviewed shared admission policy.

Bodies are uncompressed JSON, at most 65,536 bytes, with UTF-8 (quoted or unquoted)
as the only explicit charset. Duplicate charset parameters, duplicate JSON members
(including escaped names), unknown fields, noncanonical encodings and invalid
proof structure fail before reservation. Bounded proof-field overflow returns 413.
Decoded client data requires string type/origin, a canonical base64url challenge
of exactly 32 bytes and an optional boolean crossOrigin. The only other permitted
member is the optional Chromium `other_keys_can_be_added_here` string with exactly
`do not compare clientDataJSON against a template. See https://goo.gl/yabPex`
(75 ASCII characters). It is non-authoritative metadata; all other values, types,
duplicates and unknown members are rejected. The existing 8,192-byte decoded
client-data bound still applies, and signed bytes are never stripped or reserialized.
These structural checks apply to all four proof stages; an oversized challenge
returns 413 before reservation. Stored challenge, origin and stage comparisons,
cross-origin rejection and cryptographic verification follow reservation.
Each mapped request has a 30-second cancellation deadline, including body reading,
database waits and verification. Timeout returns a generic 503; an already committed
reservation retains the existing ambiguous-outcome replay rules.
The exact received bytes reach the durable idempotency ledger. Structurally valid
but cryptographically invalid proofs consume the existing durable attempt budget.
Reservation commits before verification; finish uses a separate transaction.

Pending snapshots now capture RP ID, immutable opaque user handle and the selected
credential descriptor under the same authorization/lifecycle locks as the stage
effect or authorized replay. HTTP projects an explicit public allowlist: base64url
challenges/IDs, ES256, required user verification, no attestation, and the expected
stage. Initial registration excludes no credential; replacement excludes the
current one. Candidate/current/revocation assertions allow exactly their selected
credential. User-facing labels use the opaque candidate UUID, never subject/email.
Completed replays retain the committed event/version and fetch the current lifecycle.
All timestamps are UTC with Z. Internal outcomes, hex snapshots, attempts, digests
and COSE material are never response fields. `messaging_ready` is always false;
there is no messaging key_id or device execution credential.

All responses use no-store. Failures use the existing generic problem contract,
including WWW-Authenticate for 401 and Retry-After for 429/503. Raw request bodies,
tokens and verifier/storage exception details are not logged by this adapter.

## Evidence and remaining work

`make verify` covers default-disabled hosts and invalid startup settings.
`make harness-test` exercises actual HTTPS Gateway routes, signed disposable OIDC
tokens, synthetic signed WebAuthn proofs and real PostgreSQL roles: initial
activation, replacement with both proofs, revocation, exact-byte replay and fresh
lifecycle, foreign actors, client rebinding, grant revocation, body/field limits,
generic error headers, quotas and busy-verifier rejection before reservation.
Client-data regression cases cover missing/unknown/duplicate members, invalid
types and challenge encodings/lengths across all four stages. Repeated malformed
submissions leave no proof reservations and allow valid completion, while valid
structures with wrong context or signatures consume durable attempts.
The earlier transaction/verifier/role suites retain expiry, concurrency, crash,
rollback and privilege-denial coverage.

These tests do not qualify browser/authenticator UX, production TLS/OIDC/storage,
distributed quotas or first-contact/replacement peer verification. The separate
[browser module](../../clients/web/README.md) and its Chrome test do not supply a
full account UI or production deployment. Independent E02/security review, Proposed
ADRs, messaging-key binding, [native N01/N02](agent-safety.md#pending-native-checks)
and full [production P01–P03](../../tests/Harness/README.md#evidence-and-scope)
remain pending.
