# Enrollment verifier integration

F1.4 now connects **Fido2 4.3.3** to migration 004's committed ceremony
reservations in `src/Enrollment`. This is an internal library, not a live
enrollment service. Gateway, Provisioning and Workers do not reference or register
it. The subsequent [principal/role integration](enrollment-authority.md) adds migration
005 and scoped entry functions, without installing an application login or endpoint.
The harness exercises both synthetic lower-layer projections and signed OIDC
principals with in-memory WebAuthn keys and a separate disposable execution login.

## Calling boundary and transactions

The internal `CeremonyVerifier.CompleteAsync` receives a trusted `CeremonyActor`, the ceremony
UUID, stage, idempotency key and exact UTF-8 command bytes. The actor is **not an
authentication result**: the [validated-principal bridge](enrollment-authority.md#principal-mapping) constructs it
from immutable successful OIDC evidence and a checked tenant selection. Never bind it directly
from HTTP JSON or give an application the migration credential. The constructor's
connection factory is trusted infrastructure, not a request parameter; it must
return a fresh open connection without an existing transaction. No client-side role switch
occurs in this library; the entry functions use a scoped non-login executor. Runtime/provisioning credentials still cannot execute the
core SQL primitives. The dedicated enrollment role calls only the four scoped
entry functions; see the [role and pool boundary](enrollment-authority.md).

1. Copy the bounded request once and reject malformed proof projections, JSON or
   projection-field base64url encodings with `invalid_request` before opening a
   database connection.
2. Call `amdn_enrollment.reserve` in an explicit transaction. If newly reserved,
   capture its database snapshot and next-challenge decision, then **commit and
   dispose the connection**.
   Replay and denials return without another verification job.
3. Verify the request against the snapshot, outside database locks. Compare the
   exact-byte SHA-256 digest with the stored reservation digest. No caller can
   supply a successful verifier projection to this API.
4. In a separate transaction, call `amdn_enrollment.finish` with only the verified public
   projection, or `amdn_enrollment.fail` for a generic `invalid_proof` result after bounded
   CBOR, profile or cryptographic rejection, including out-of-range COSE integers.
   These failures consume the durable attempt budget. The existing SQL rechecks
   authorization, lifecycle versions, counter/BE, stage, digest, deadlines and
   uniqueness. Commit before returning an internal result. Fresh next-stage
   challenges use the platform cryptographic RNG.

Ambient transactions are rejected, so they cannot undo a supposedly durable
reservation. Cancellation, lost connections and unexpected commit/audit failures
leave an already committed reservation intact. Exact retry of an unresolved
reservation returns `unavailable`; this slice does not add an automatic recovery
worker, retry verification or claim that a lost response means rollback. The
[transaction reference](ceremony-transactions.md) owns lifecycle and replay rules.

The return value is internal SQL JSON, **not an HTTP response DTO**. The future
adapter must build the staged contract responses, options and generic errors;
both internal `invalid_request` and `invalid_proof` map to the contract's generic
HTTP 400 `invalid_request`, not a new public error schema.
It must also enforce HTTPS, content type, no compression, headers, authentication,
request/concurrency budgets and timeouts before enabling routes. Byte limits here
do not replace transport or operation budgets.

## Verification profile

The pinned [Fido2 implementation](https://github.com/passwordless-lib/fido2-net-lib/tree/4.3.3)
performs standard registration/assertion verification. The adapter enforces the
additional [AMDN profile](enrollment-credential-design.md), using only the stored
challenge, exact RP/origin, allowed credential, handle, counter and BE. It never
accepts client-supplied options, trusts forwarded headers, uses AppID, fetches
metadata, verifies attestation certificates or negotiates a weaker algorithm.

- Strict UTF-8 JSON, depth at most 16, duplicate names rejected including escaped
  equivalents, exact AMDN fields, empty client extensions and canonical unpadded
  base64url. The [contract limits](../protocols/device-enrollment.md#browser-projection-and-bounds)
  apply before Fido2 parsing; registration authenticator data is bounded during
  CBOR preflight after reservation.
- Client data permits only type, challenge, origin and optional `crossOrigin:
  false`. No topOrigin, tokenBinding or unknown client-data fields are accepted in
  this first profile. Origin comparison is exact, even where library URL
  normalization would accept an equivalent spelling. Configured origin must be
  canonical HTTPS and its host within the configured RP's DNS suffix.
- Registration preflights a definite CBOR map with exactly `fmt: none`, empty
  `attStmt` and bounded authData. It requires AT, forbids ED, and compares the
  attested ID with id/rawId. Public COSE keys contain exactly EC2, ES256, P-256,
  and 32-byte x/y; the platform validates the point. Definite maps, reordered
  labels and non-minimal valid encodings normalize to one canonical public key
  for database uniqueness. Indefinite maps, extra/private labels, extensions and
  trailing CBOR are rejected. This is profile parsing, not custom cryptography.
- Assertions require the exact stored credential, no AT/ED/trailing authenticator
  data, and the stored user handle when supplied. Absent/null handles are allowed
  only within the already authorized, single-credential reservation. Fido2 checks
  the signature, RP hash, challenge, type, UP/UV, flags and counter. The adapter and
  commit transaction additionally compare BE with registration.

The library registration uniqueness callback returns true without checking
uniqueness: retained credential-ID and normalized-public-key uniqueness is decided
by SQL at commit, including concurrent registrations. Registration alone cannot activate a device;
the next signed assertion must prove possession. Replacement also requires the
old credential's separate proof. No plaintext, private key, raw proof, attestation
or token is persisted or logged by the adapter. Exception text from proof parsers
is not exposed; infrastructure failures propagate for the caller to handle safely.

## Evidence and remaining work

The harness sends synthetic, actually signed ES256 responses through the adapter
and real database transactions. It covers initial enrollment, replacement,
revocation, historical replay, counter/flag/profile rejection, malformed encodings,
foreign owners, retained-key uniqueness, changed authority and interrupted work.
Tests prove the reservation is committed and its locks released before completion.
The earlier isolated verifier experiment remains a separate raw-library baseline;
its fixture generator is not linked into this component.

The verifier dependency is pinned and hash-locked with transitive dependencies.
Its upstream MIT license and dependency notices still require the separate
redistribution review before binary distribution. Advisory checks remain enabled;
successful restore is not a security audit or independent crypto approval.

**Live enrollment remains pending**: no deployed HTTP adapter, browser adapter,
application budgets or production rollout is provided.
[Trusted SQL administration](enrollment-administration.md) now supplies configuration
and grant commands. Principal and role integration have test-probe evidence in the
[authority guide](enrollment-authority.md). Browser/authenticator compatibility, real OIDC
assurance and integrated API races require later validation. One active logical
device is not a non-copyable key guarantee. Messaging readiness/key binding and
independent peer verification remain separate requirements. E02 and ADR approvals,
[native N01/N02](agent-safety.md#pending-native-checks) and full
[production P01–P03](../../tests/Harness/README.md#evidence-and-scope) remain pending.
Dependabot #10 was separately evaluated and closed without merging; see the
[compatibility evaluation](../../clients/crypto/README.md#pr-10-compatibility-evaluation).
Security hooks and PR/CI gates remain intact.
