# F0.4 HTTP and envelope draft

Status: Proposed, version `0.2.0-draft`. The [OpenAPI 3.1.1 description](openapi.json)
covers the blueprint operations, F1.3 platform membership extension and F1.4 staged credential commands. See the [repository README](../../README.md)
for current implementation status.

The source JSON is the schema authority for this draft. The
[identity model](identity-and-data.md), [authorization matrix](authorization.md)
and [delivery protocol](delivery.md) define semantic checks that JSON Schema
cannot enforce. Validate with `make contracts-restore contracts-test` using Python
3.12 and the hash-locked development dependencies in tests/Contracts. CI runs
these checks in `make verify`; no production dependency is added.

The [F1.3 guide](../security/provisioning-owner-access.md) documents the implemented
provisioning and owner-read subset, including its stricter 16 KiB command bound,
separate operator host and explicit verified tenant selection. Other operations
remain proposed and unimplemented.

The old single-step device draft is replaced by the [staged enrollment/revocation
contract](device-enrollment.md). Its six commands are proposed and unimplemented;
their stricter 64 KiB body bounds, proof stages, origin binding and replay rules
override the common defaults below. Credential enrollment supplies no message key
or messaging authority; a separate reviewed binding is required.

## Common contract

Require HTTPS and a validated access token. Derive tenant/user/postman for tenant
operations from a verified active membership and device from the authenticated
device binding. Never use the submitted body to establish the caller's identity.
Platform provisioning uses the separate authority described in the
[authorization matrix](authorization.md). Object checks and per-operation scopes
are listed in OpenAPI; a bearer scheme declaration does not enforce any of them.

Requests are strict UTF-8 JSON with no duplicate object keys or unknown fields;
reject compressed command bodies in this draft. IDs use canonical lowercase UUID
text and dates UTC RFC 3339 `Z` values. Decode base64url strictly (no padding,
noncanonical trailing bits or alternate alphabet) before applying byte limits.
Regex/length schema checks alone do not prove canonical binary encoding or valid
cryptography. No client plaintext, private keys or recovery secrets are allowed.

Draft review bounds: ciphertext up to 128 KiB decoded, JSON command body up to 256 KiB, page size 1–100, cursor up to 1024
characters, idempotency key 16–128 visible ASCII characters. Submitted expiry must
be after admission time and no later than 24 hours after it. These are proposed
testable bounds, not measured capacity or approved production quotas. Per-tenant
rate, storage and retry budgets still require A06 sign-off; fail closed without
configured budgets rather than silently allowing unlimited work.

Errors use `application/problem+json` following RFC 9457, with a stable code,
status and request correlation ID. Error detail must exclude identities a caller
cannot access, tokens, ciphertext and internal exception text. Missing and hidden
resources share 404 `not_found`. Authentication failures use 401 plus
WWW-Authenticate; authorized callers may receive generic 403 `forbidden` for a
disallowed action. 409 signals conflicting idempotency/state/key snapshots, 410
an expired cursor, 412 a stale policy precondition, 413 a size bound, 415 an
unsupported media type or content encoding, 429 a quota,
and 503 transient inability to accept. Retry-After accompanies 429/503.

## Commands and replay

Commands marked with the required Idempotency-Key parameter in [OpenAPI](openapi.json)
use the replay contract below. See the [F1.3 provisioning contract](../security/provisioning-owner-access.md#atomic-provisioning-grants-and-audit)
for platform actor scoping and target-tenant binding.
Scope other command keys to authenticated tenant/actor/operation.
Compute the request digest over the exact decompressed-free UTF-8
JSON bytes and operation, not a client-supplied digest. No JSON canonicalization
scheme is selected for crypto here. Clients retry identical bytes with the same
key; any byte difference with that key returns 409. Reserve key, effect and result
atomically. Authenticate and authorize every retry before returning stored results.
Do not reveal a prior result after its owner loses access.

Message client_message_id is additionally unique per sender. Another key reusing
that ID returns 409, even with an identical body. The original replay returns the
original 202 admission result and Location; fetch status for subsequent progress.
If the response is lost after commit, retry must recover that result. Admission
failures do not create an accepted envelope. Retention/tombstone windows need A06
approval before eviction can be enabled.

Ack is naturally idempotent on delivery and receipt kind, returning the original
receipt for the same still-authorized device. Policy changes use If-Match and
versioned atomic update; retrying a completed patch with the old ETag returns 412,
so the owner reads current policy before deciding whether to try again.

## Envelope boundary and cryptographic dependencies

Submission omits sender identity and server envelope ID. It includes client
message/conversation correlation IDs, recipient address plus expected immutable
device/key IDs, client-created timestamp, expiry and opaque encrypted payload.
Admission resolves the address under policy, compares the expected device/key
snapshot, derives the sender, and stores immutable accepted metadata. Clients
must not treat a declared sender in a directory, job or ciphertext wrapper as
proof. The admission response is defined by the `Accepted` schema in
[OpenAPI](openapi.json); it is distinct from subsequent delivery status.

Before any production profile can be enabled, E01–E06 must specify authenticated
binding of protocol/version, message and conversation IDs, sender and recipient
tenant/user/postman/device/key identities, expiry and content type; exact bytes,
canonicalization and integrity failure handling belong to the reviewed protocol
adapter. Server-added IDs/timestamps cannot be retrospectively claimed as
authenticated sender data. Reconcile that distinction in E02/E05 review.

The profile field is syntactically a versioned identifier, not an allowlist.
Examples use `amdn-synthetic/1`, which is **not** an approved profile. The eventual
server must reject every unapproved profile and stale key binding. Do not equate
the isolated ts-mls wire records with this draft HTTP envelope or freeze the
adapter around the candidate. PR #10 was separately evaluated and closed without
merging; see the [compatibility evaluation](../../clients/crypto/README.md#pr-10-compatibility-evaluation).
No crypto pin changes.

## Decisions and approval gates

| ID | Still required | Owner role / evidence |
| --- | --- | --- |
| A01 | Review logical schema, immutable ID choice and external identity mapping | Maintainer/backend; reviewed F1 constraints and lifecycle |
| A02 | OIDC provider, WebAuthn credential integration/security review, messaging-key binding, address normalization and reassignment | Identity/crypto reviewers; E02 enrollment and key-change tests |
| A03 | Exact RLS roles, narrow router operations and cross-tenant transaction privileges | Database/security; forbidden-query and race evidence |
| A04 | Approve envelope encoding, crypto profile, bounds and version compatibility | Crypto/API; E01–E06 and interoperability evidence |
| A05 | Review transition, expiry, revocation and receipt ordering details | Delivery/policy; executable F0.5 races; durable-storage ack meaning selected by maintainer |
| A06 | Retention, cursor algorithm, quotas, retry ceilings and cleanup windows | Platform/maintainer; load, concurrent-commit and restart evidence |
| A07 | Approve all endpoint scopes/errors and bind them to implementation | API/security; two-tenant negative integration suite |

No architecture approval, production encryption selection or F0 completion is
recorded by these artifacts. [N01/N02](../security/agent-safety.md#pending-native-checks)
remain pending. The [F0.5 harness](../../tests/Harness/README.md#evidence-and-scope)
records fixture evidence and the remaining production integration requirements;
F1.3 additionally validates the implemented provisioning/owner-read subset against
actual application hosts, while the remaining contracts and acceptance gates stay
pending.

References: [OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html),
[JSON Schema 2020-12](https://json-schema.org/draft/2020-12),
[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html),
[validator documentation](https://openapi-spec-validator.readthedocs.io/en/latest/).
