# Device persistence foundation

F1.4 now has an embedded storage migration and an internal membership-scoped
metadata reader. This is **not a working enrollment service**. The
[staged contract](../protocols/device-enrollment.md) remains proposed; all six
HTTP commands and grant-administration API remain unimplemented. The later
[ceremony transaction layer](ceremony-transactions.md) adds reservations and atomic
storage effects; the [isolated verifier bridge](enrollment-verifier.md) connects
proofs to them; the [principal/role bridge](enrollment-authority.md) supplies internal
authenticated execution. Public API integration remains pending. No Gateway
route or DI registration is added, and existing application roles cannot write
device records.

## Records and constraints

Migration 003 adds `amdn_identity.device_subjects` and `amdn_identity.devices`.
See [applying migrations](identity-persistence.md#applying-migrations) for the
deployment runner, migration sequence and checksum rules.

A device subject fixes one random 32-byte WebAuthn user handle for each
`(tenant_id, user_id, rp_id)`. Handles are unique within an RP and retained across
device replacement. They cannot be rebound or deleted. RP strings are bounded
lowercase DNS names; this is storage syntax, not an RP/origin allowlist or browser
qualification. Deployment configuration must still establish the exact RP.

A device reserves a server UUID under that composite owner/RP. Credential ID,
normalized public COSE key, BE, BS and counter are either all absent or all present.
The whole credential can be attached once while pending. Owner, device UUID, RP,
profile, configuration version, creation time, credential ID/key and BE are
immutable after binding. There is no private-key, messaging-key, plaintext or
recovery-secret column. The read DTO exposes none of the credential material.

`pending` is a storage reservation, not a ceremony stage. Multiple pending or
abandoned device rows may be retained for an owner. The proposed
[one-unfinished-ceremony rule](../protocols/device-enrollment.md#commands-and-authority)
is now enforced by the separate [ceremony ledger](ceremony-transactions.md); the
device table itself does not enforce it.

The storage representation for a verified ES256 key is the fixed 77-byte public
COSE map `{1:2, 3:-7, -1:1, -2:x, -3:y}`, with 32-byte x/y coordinates and
shortest, ordered CBOR encodings. This uses the [COSE EC2 parameters](https://www.rfc-editor.org/rfc/rfc9053.html#section-7.1.1)
and [deterministic CBOR rules](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1).
The SQL shape check excludes extra/private parameters and alternative encodings,
so the unique `(rp_id, public_key_cose)` constraint cannot be evaded by reordering
map fields. It does **not** validate a curve point, signature, attestation or key
possession. See the [verifier boundary](enrollment-verifier.md#verification-profile)
for validation and normalization before storage. Normalizing stored public material
must never rewrite signed client/authenticator bytes before verification.
The synthetic test encoder is not application crypto.

Credential IDs are bounded at 1–1,023 decoded bytes and unique per RP across every
retained state. The same applies to normalized public keys. Retaining abandoned
and revoked records prevents credential/key reuse. There is no automatic cleanup.
A later A06 retention migration must preserve this attribution and uniqueness.

| Storage transition | Database condition |
| --- | --- |
| Insert → pending | Server timestamps and record version 1; composite owner/RP exists |
| pending → credential_active | Complete credential; unique active `(tenant_id,user_id)` across RPs |
| pending → abandoned | No active identity is created; bound credential retained if present |
| credential_active → revoked | Activation retained, revocation timestamp assigned; terminal |
| revoked / abandoned → anything else | Rejected |

Terminal records are immutable and deletion is rejected. The database controls
lifecycle timestamps and increments `record_version` only on actual changes.
This is a per-row optimistic storage version, **not** the user's identity version.
The unique active-device index handles concurrent storage writes; it does not
supply step-up, proof order, expected identity-version checks, atomic audit or
replay. Synthetic owner transactions exercise rollback and replacement of storage
rows only. No production activation/revocation primitive is exposed in this slice.

BE cannot change after registration. BS can be true only when BE is true. Counters
fit unsigned 32 bits and cannot decrease. Equal counters are allowed for metadata
and lifecycle updates; the [ceremony transaction](ceremony-transactions.md) separately
rejects non-increasing nonzero assertion counters in trusted verifier projections,
while permitting zero-to-zero under the selected profile. The device-table
constraints alone are not replay protection.

## Role and read boundary

Both tables enable and force RLS. The non-login migration owner has an explicit
owner policy and remains a trusted administrative boundary. Runtime and provisioning
groups receive no device INSERT, UPDATE, DELETE, TRUNCATE or handle-table privileges.
Migration 005 adds the [scoped ceremony executor and execute-only application boundary](enrollment-authority.md#postgresql-roles-and-rls);
that guide owns the mutation privileges and pool requirements.

Runtime receives SELECT on metadata columns only. RLS requires transaction-local
tenant/user/issuer/subject context matching an active membership, tenant and user,
plus an active personal postman. Foreign owners in the same tenant and foreign
tenants are hidden. Pending and retained terminal metadata remain readable to the
current owner; they are not usable credentials or messaging identities.

`DeviceMetadataStore.ReadAsync` accepts the principal produced by configured OIDC
validation, an explicit tenant selector and a device UUID. It resolves current
membership under existing shared lifecycle locks, applies transaction-local
context and reads one owner's metadata through the guarded runtime pool. Missing,
foreign and denied records all return null. The result is a statement-consistent
observation, not a grant or lock against later device changes. It is not exposed
as an endpoint: any future operation still requires its scope, current object
grant, step-up and proof conditions. F1.3's postman.read grant is unchanged.

As with [identity persistence](identity-persistence.md#database-authority), arbitrary
SQL execution with the runtime credential can choose external subject/context.
RLS does not contain a fully compromised service. Public callers must never supply
SQL, constructed principals or context directly. No device handle or public key
is returned by this metadata adapter.

## Evidence and remaining work

`make harness-test` runs the actual migration and metadata adapter with disposable
PostgreSQL, generated identities and separate logins. Device cases cover foreign
owner/tenant denial, current lifecycle denial, empty/partial/mismatched context,
size-one pool reuse and cancellation rollback, absent application writes and
credential-column access, immutable bindings, canonical storage shape, retained
uniqueness, competing activation, transaction rollback and database restart.
All device writes in these cases use the trusted migration owner as **synthetic
setup**, not a deployed enrollment/proof implementation or verified user ceremony.

The [ceremony transaction layer](ceremony-transactions.md) now adds durable
challenge/attempt/replay/audit storage and lifecycle effects with checks after
waits. See the [authority guide](enrollment-authority.md) for subsequent application
execution authority and the [verifier guide](enrollment-verifier.md#evidence-and-remaining-work) for proof integration
and remaining application work. Explicit grant
administration, browser interoperability and messaging-key binding remain open.
One active logical device makes no physical-device or key non-copyability claim;
independent peer verification is still required before first send and replacement.

Live enrollment validation remains pending. [Native N01/N02](agent-safety.md#pending-native-checks)
and full [production P01–P03](../../tests/Harness/README.md#evidence-and-scope) remain
pending despite this storage evidence. ADRs remain Proposed; no F0 or independent
crypto review is declared complete. Dependabot #10 was separately evaluated and
closed without merging; see the
[compatibility evaluation](../../clients/crypto/README.md#pr-10-compatibility-evaluation).
Pins and all repository/security gates remain unchanged.
