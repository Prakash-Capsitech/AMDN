# F0 encryption feasibility plan

Status: Pending. No cryptographic protocol or implementation has been selected.

Compare vetted MLS 1.0 and Signal-protocol implementations for the actual
React/TypeScript client environment. For each candidate, record upstream version,
license and distribution obligations, maintenance activity, audit evidence,
browser/WASM compatibility, key persistence and required server directory data.
Do not build a new cryptographic protocol to satisfy a missing library feature.

## Required experiment

1. Enroll two independent devices and publish only authenticated public key data.
2. Establish a session and encrypt while Bob is offline; deliver stored ciphertext
   after reconnect and decrypt only on Bob's device.
3. Reject tampering, replay and incorrect sender/recipient/session bindings.
4. Exercise duplicate and reordered messages and crash/restart of client state.
5. Replace a device key: show the warning and apply explicit rekey rules.
6. Demonstrate provider storage/logs cannot reveal plaintext or private keys.
7. Explain first-contact verification, recovery limits and compromise assumptions.

Produce runnable spike code, versions/licenses, captured results and a reviewer
recommendation. Record the selected protocol/library in a new or revised ADR only
after this evidence is reviewed. A passing liveness test is not crypto evidence.
