# E02 device enrollment trust review

Status: Initial engineering assessment, 12 November 2026. **E02 remains open.**
No independent crypto/security reviewer is nominated. The follow-up
[credential design](enrollment-credential-design.md) selects WebAuthn registration
plus assertion and records pinned verifier evidence; production approval remains
pending. The maintainer selected one active logical device identity
and mandatory independent verification before sending, including after key
replacement, on 12 November 2026. Those product decisions do not approve a
cryptographic design. This is a review packet and an authentication prerequisite
for F1.4, not approval to enable enrollment or production messaging.

## Findings and implementation boundary

The [draft identity contract](../protocols/identity-and-data.md) requires ownership,
step-up, proof of possession and atomic replacement. Its `DeviceRequest` JSON
does not specify a possession ceremony. Uploading a public package with a bearer
token proves neither possession of private keys nor independent recipient identity.
Implementing that draft as an endpoint would leave its central condition empty.

The OIDC adapter previously discarded authentication context/time. This slice
adds an opt-in, tested [step-up prerequisite](oidc-authentication.md#device-step-up-prerequisite).
It checks verified login evidence only. It creates no device/key/challenge rows,
changes no grants and maps no device endpoint. `/v1/devices` stays unimplemented.
The draft OpenAPI stays Proposed; its legacy single-step enrollment is deprecated
in favor of the credential design and must be replaced before implementation.
There is no placeholder verifier, opaque-key
acceptance path or import of the experimental crypto package.

## Enrollment: separate the proofs

The design must demonstrate these before a device becomes messaging-ready.
Credential enrollment and later messaging-key binding are separate authorized
operations; completing the former alone grants no messaging authority:

1. Current tenant membership resolved from verified issuer/subject, explicit
   `device.manage` scope and a current object-level enrollment grant. F1.3's
   `postman.read` grant confers no enrollment authority.
2. Recent user authentication at an issuer-specific assurance level. An `amr`
   value such as `mfa`, a scope or a new token issue time alone is insufficient.
3. Possession of the new authentication credential during enrollment, followed by
   a separately reviewed messaging-key possession/binding operation before
   messaging activation. Proving one key does not prove another.
4. A single-use, expiring ceremony bound to tenant, user, operation, expected
   identity version, replacement target, exact public material and originating
   client context. These cannot change after challenge issuance. Retrying a
   consumed proof must not authorize a new operation.

| Candidate | Useful property | Remaining problem / disposition |
| --- | --- | --- |
| WebAuthn registration plus subsequent assertion | Standard origin/RP binding and user verification | Selected engineering direction in ADR 0011; Fido2 4.3.3 exercised in an isolated experiment. No attestation is not hardware provenance or possession proof; the subsequent assertion supplies possession evidence. It does not validate an MLS package. |
| OAuth DPoP | Standard sender-constrained tokens and proof checking | Requires authorization-server support and a complete resource-server verifier. Current bearer handling does not implement it. It does not sign the request body or prove a separate encryption key. |
| Bare MLS KeyPackage upload | Public protocol input for offline initiation | Rejected as sufficient account/device authentication. Identity/signature-key binding needs a reviewed MLS authentication service; fixture pins cannot supply it. |
| Custom signed enrollment JSON | Simple-looking challenge/signature exchange | Not selected: inventing a crypto protocol conflicts with ADR 0007. |

The [selected profile](enrollment-credential-design.md) separates interactive
WebAuthn authorization from messaging credential binding. Its experiment does
not approve the library for production. Backup-eligible credentials may exist on
multiple authenticators. One active server record does not prove one physical
device; rejecting backup eligibility without trusted attestation also does not
establish hardware non-exportability. The selected guarantee is one active
logical identity per tenant/user, with no assurance that keys cannot be copied.
Browser qualification remains pending. See [WebAuthn backup state](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-credential-backup)
and [verification ceremonies](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-rp-operations).

[DPoP sections 7 and 11.7](https://www.rfc-editor.org/rfc/rfc9449.html#section-7)
cover proof validation and request-integrity limits. [MLS sections 5.3 and 16.10](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3)
cover identity/key association and authentication-service compromise. Neither
standard supplies AMDN's enrollment policy automatically.

## First-contact verification

An authenticated directory is still a provider claim. TLS and valid package
signatures do not prevent first-contact key substitution by that provider.
Selected product requirement: independently verify the complete peer identity/key
binding before sending any message, with an explicit unverified state and no
automatic acceptance. Include immutable tenant/user/device identity, protocol
profile and identity-key fingerprint; review encoding/display against ambiguous
concatenation and truncated comparisons. No fingerprint format is implemented.

Use a separately authenticated channel or in-person comparison. A QR code fetched
from the same provider directory is not independent verification. Trust-on-first-use
does not satisfy the selected requirement and must not be an alternate send path. Key transparency
remains a later extension under ADR 0007, not an existing mitigation.

## Replacement, revocation and retained attribution

Proposed transaction requirements preserve the draft's invariants:

- Lock current membership/user, then check grant, step-up freshness, proof
  expiry/consumption and expected version at the effect boundary, including after
  lock waits. Recheck current authorization on idempotent retries.
- First enrollment requires no active device. Replacement explicitly names the
  current active device. Lock ordering, unique active-device constraints and
  conditional version increments arbitrate enroll/replace/revoke races.
- Commit proof consumption, device/key changes, replay result and minimal audit
  atomically. Failure leaves no partial active identity. Gateway's read-only
  runtime role must not receive general device-table write access.
- Revoke old credentials and retain immutable tombstones. Existing deliveries
  retain their original device/key attribution. Do not relabel them or introduce
  provider recovery keys. Recheck revocation at device-sensitive execution, not
  only at login or queue submission.
- Show a persistent key-change state, stop the old session, require independent
  verification and start a fresh encryption session. API success or warning
  dismissal must not silently restore peer trust. Lost-device recovery needs a
  reviewed assurance policy; an ordinary session alone is insufficient.

These are acceptance requirements, not implemented SQL, UI or race-test results.
Unenrollment and replacement contracts must be reviewed together.

## Client-distribution trust

A provider able to replace web JavaScript can capture plaintext, invoke signing
or falsify verification UI. Non-exportable keys do not prevent their misuse by
same-origin code. CSP, pinned dependencies and subresource integrity reduce some
injection/supply-chain risks, but not an operator's control of the trusted page
and its policy/integrity metadata. This is boundary analysis, not evidence from
an AMDN client. See the scope of [Subresource Integrity](https://www.w3.org/TR/2016/REC-SRI-20160623/).

Before claiming resistance to a malicious delivery provider, choose a distribution
model with an independently controlled verification/update trust root, review
signing/rollback policy and test compromise/recovery. A separately distributed
client is a candidate, not a guarantee. If the product trusts provider-served web
code, explicitly review whether that limitation meets its threat model. Neither
choice is accepted here.

## Decisions and exit evidence

| ID | Decision / evidence | Owner and state |
| --- | --- | --- |
| E02-D1 | One active logical identity; WebAuthn registration plus assertion for enrollment; no hardware/non-copyability claim | Logical-device guarantee selected by maintainer 2026-11-12; credential profile specified in ADR 0011, experiment passed; browser/application integration and independent review pending |
| E02-D2 | Independent verification required before first send and after key replacement | Maintainer selected 2026-11-12; comparison format, UX and lost-device recovery still pending crypto review |
| E02-D3 | Client distribution/update trust root and malicious-provider limitation | Maintainer and security reviewer; pending |
| E02-D4 | Messaging credential binding and exact-version protocol/implementation review | Independent crypto reviewer not yet nominated; E01/E06 open |

Record reviewer, date, selected profile, residual risks and evidence before
acceptance. An agent review, no-mistakes pass or PR merge is not independent
cryptographic approval. ADR 0007 remains Proposed.

After these decisions, remaining F1.4 work is: revise the ceremony contract;
implement proof verification and narrow persistence authority; add enrollment,
replacement/revocation and client UX; test real HTTP/PostgreSQL boundaries.
Negative cases must cover foreign owner/tenant/grant, stale step-up, substituted
keys/context, wrong origin/RP, expired/reused proofs, simultaneous replacement,
revocation during lock waits, lost-response retries and audit/commit failure.
Client evidence must show blocked unverified first contact, visible replacement
and preserved old-key attribution.

This slice tests only signed step-up evidence, configuration, freshness, scope
and default denial. [Native N01/N02](agent-safety.md#pending-native-checks) and
[production P01–P03](../../tests/Harness/README.md#evidence-and-scope) remain
pending. Dependabot #10 stays deferred; crypto pins are unchanged.
