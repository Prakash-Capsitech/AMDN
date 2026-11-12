# F0.3 encryption feasibility

Status: Runnable candidate experiment and initial assessment, 12 November 2026.
**Not approved for production.** ADR 0007 remains Proposed. Human architecture,
cryptography and license review are pending; this does not close F0.1–F0.3.

## Experiment and reproduction

[clients/crypto](../../clients/crypto/README.md) contains two independent client
state objects using MLS 1.0 through pinned ts-mls 1.6.4, with cipher suite
MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519. The spike adds no cryptographic
primitive or key-exchange protocol. It is not imported by the backend or web app.

Use Node 24.22.3 from .nvmrc, npm, Python 3 and Chrome for the browser check:

```sh
make crypto-restore
make crypto-test
make crypto-spike
make crypto-browser
```

Restore uses the integrity-locked dependency graph with lifecycle scripts disabled.
The local run used Node 24.22.3, npm 11.19.1 and Chrome 157.0.8103.50 on Linux.
The browser runner serves only clients/crypto on a random loopback port, uses a
disposable profile and leaves Chrome's sandbox enabled. This is a browser smoke
test, not React integration.

Alice and Bob generate independent credentials locally. Bob publishes a public
KeyPackage before going offline. Alice produces a Welcome and ciphertext without
calling Bob. A simulated relay stores explicit wire records and public routing.
Bob later processes the Welcome, restores his serialized state, decrypts the
queued message and sends an encrypted reply. No socket transport, provider API,
real tenant authorization or storage service is represented. Both clients run in
one process/page: logical key separation, not an OS isolation proof.

## Evidence from this run

The 12 executable scenarios in spike.test.mjs passed locally. The browser
exchange also passed. Commands return nonzero on an unexpected result and print
only synthetic test names/status; the demo never prints keys or plaintext.

| Scenario | Observed result | Boundary of evidence |
| --- | --- | --- |
| Offline initiation, delayed decrypt and reply | Passed in Node and Chrome | One page/process, simulated transport |
| Ciphertext mutation | Rejected; original still decrypted | One-bit mutation, not fuzz coverage |
| Route sender/recipient/session/message-ID mutation | Rejected | Labels bound through MLS authenticated data |
| Rewrite both visible authenticated data and route ID | Cryptographic verification rejected | Matching visible metadata alone is not trusted |
| Public KeyPackage signature mutation | Rejected even with matching pins | Identity pin and package signature are separate checks |
| Reordering and duplicate receipt | Two messages decrypted out of order once; repeats rejected | Bounded retention of 10 generations in one epoch |
| Restore committed private state | Continued delivery; consumed-message replay rejected | Serialization only, no real crash or durable transaction |
| Restore stale private state | **Replay succeeded**, as the test intentionally demonstrates | Rollback-resistant storage is a release blocker |
| Replace Bob's device | Old pins refused new key; new pins/session worked; old device rejected new traffic | Full reset; no in-place rekey or recovery |
| Deliver to another group | Rejected | Session and authenticated metadata checks |
| Inspect provider records | Allowlisted fields/wire bytes; plaintext canary/checkpoint absent | Data-flow assertion, not proof against compromised process/provider |
| Malformed input and overlapping operations | Rejected | No cross-tab or multi-process locking proof |

The successful demo prints offlineExchange, restoredReceiver and reply as pass,
providerRecords as 3, and productionApproved as false. npm audit reported zero
known vulnerabilities in six production dependencies on this date; that is an
advisory lookup, not an audit or security approval.

## Trust, state and key custody

The harness supplies an out-of-band mapping from full synthetic tenant/user IDs
to signature public keys. Library credential validation uses those exact pins;
it does not accept an unauthenticated directory response. fixturePins is only a
test helper. Real enrollment, account binding, first-contact verification, pin
distribution and key-change confirmation UX remain unimplemented. A malicious
provider can substitute first-contact keys or serve malicious client code unless
the eventual trust/distribution design addresses it.

MLS handles message signatures and encryption. This two-member experiment binds
route labels via authenticated data and validates the expected roster on join.
The 1.6.4 high-level application result does not expose the verified sender leaf
index. This is not a general multi-member identity adapter or a third-party-
verifiable authorship/receipt mechanism. Review signer attribution before
expanding the API, adding members or implementing production history.

Each client owns its private KeyPackage, group secrets and serialized checkpoint.
Consumed library key buffers are zeroed on successful transitions. JavaScript
GC, retained key packages, clones and checkpoints prevent any claim of complete
memory erasure. Checkpoints are unencrypted synthetic memory objects, never relay
records, log entries or disk files. A production store needs confidentiality,
authenticity, atomic state-and-outbox/inbox commits, concurrency control and a
rollback policy. Sending before durable state commit can reuse state after a
crash; this spike has no durable-send guarantee.

Replacement requires new pins and a fresh conversation. It does not silently
recover old messages, reuse old state or introduce a provider recovery key.
Lost private keys mean old ciphertext is unavailable to the replacement. The
trust decision is simulated, not an implemented UI.

## Candidate assessment

These are experiment findings and recommendations, not final selections. Sources
and versions were checked on 12 November 2026.

| Candidate | Integration and maintenance | License and audit status | Recommendation |
| --- | --- | --- | --- |
| ts-mls 1.6.4 | TypeScript/JS; this version ran in Node/Chrome; stable registry release dated 28 August 2026; v2 prerelease API differs | MIT; upstream says no formal audit and single-volunteer maintenance | Disposable candidate only; independent review required before adoption |
| Signal libsignal 0.107.0 | Official Rust-backed Java/Swift/TypeScript bindings; released 10 November 2026; Node native binaries, no browser/WASM path demonstrated here; external use unsupported | AGPL-3.0-only; source/distribution obligations need a dedicated license decision; exact-version audit coverage not established here | Protocol alternative; not executed or bundled |
| OpenMLS 0.9.0 | Rust MLS; released 25 August 2026; JS/WASM compilation feature, but upstream describes WASM as build-only rather than tested supported target | MIT; verify exact-version audit coverage and transitive notices; no audit conclusion here | Separate browser/WASM comparison candidate; not executed |

Sources: [ts-mls versioned README](https://github.com/LukaJCB/ts-mls/tree/v1.6.4),
[ts-mls security policy](https://github.com/LukaJCB/ts-mls/blob/v1.6.4/SECURITY.md),
[Signal release](https://github.com/signalapp/libsignal/releases/tag/v0.107.0),
[Signal README/license](https://github.com/signalapp/libsignal/tree/v0.107.0),
[OpenMLS release](https://github.com/openmls/openmls/releases/tag/openmls-v0.9.0),
[OpenMLS platform guidance](https://github.com/openmls/openmls), and
[MLS standard](https://www.rfc-editor.org/rfc/rfc9420.html).

The pinned runtime graph is ts-mls 1.6.4, @hpke/core 1.9.0, @hpke/common 1.13.0,
@noble/curves 2.0.1, @noble/hashes 2.0.1 and @noble/ciphers 2.1.1. All six licenses
are MIT; preserve their [notices](../../clients/crypto/THIRD_PARTY_NOTICES.md) with
redistributed copies. AMDN remains private without an open-source license grant.
No Signal/OpenMLS code is redistributed here.

Integration finding: importing ts-mls 1.6.4's root entry point initially failed
because @noble/hashes was absent. Explicitly pinning the optional curve package
supplies that dependency. The lockfile records the working graph; the minimal
upstream install example alone was insufficient in this environment.

## Remaining gates

| ID | Required before production selection |
| --- | --- |
| E01 | Independent protocol/implementation review and exact-version audit evidence |
| E02 | Identity enrollment, first-contact verification, key replacement UX and client-distribution trust |
| E03 | Secure browser storage, atomic crash recovery, rollback policy, cross-tab locking and key lifecycle |
| E04 | React/TypeScript adapter, Firefox/Safari/mobile tests, bundle sizing and dependency maintenance plan |
| E05 | Cross-implementation interop, malformed-input fuzzing, epoch/rekey/expiry tests and performance evidence |
| E06 | Maintainer license/distribution review, named crypto reviewer and separate ADR acceptance |

[Native agent checks](agent-safety.md#pending-native-checks) remain pending from
PR #2. Chrome crypto success does not activate Codex hooks or prove Claude/Codex
native sandbox integration. Neither those checks nor F0 security review is closed.
