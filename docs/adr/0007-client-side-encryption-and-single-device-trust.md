# ADR 0007 Client side encryption and single device trust

Status: Proposed
Date: 2026-11-12
Decision owner: AMDN maintainer and relevant architecture/security reviewers
Source: implementation plan sections 2, 8, 18, 20

## Context

The delivery provider must route and store messages without holding message decryption keys. Library and trust choices are a critical feasibility dependency.

## Proposed decision

Use an established vetted E2EE protocol implemented on user devices. Evaluate MLS 1.0 and a mature Signal-protocol implementation in F0.3; do not choose a library from this ADR alone. Start with one active device per user. Devices hold private keys. Provider services hold ciphertext, authorized public key material and routing metadata. Expose key changes and require explicit session handling on replacement.

## Alternatives and scope

Custom cryptographic protocols, provider-controlled silent recovery keys and server-side plaintext inspection are rejected. Multi-device and key transparency are later extensions.

## Consequences

A provider-controlled key directory can substitute keys; visible warnings alone do not eliminate first-contact trust risk. Device loss may make old ciphertext unrecoverable. Future content-aware agents need a separate explicit trust decision.

## Acceptance evidence and open questions

Prove offline session initiation, sender authentication, metadata binding, tamper/replay rejection, rekey behavior and crash-safe client state. Review browser compatibility, licensing, maintenance and audit evidence. Record human security review before accepting the protocol and library.

Approval: Not recorded. Record reviewer, date and evidence before changing status.

F0.3 now has a [candidate experiment and assessment](../security/encryption-feasibility.md).
The Node/Chrome exchange is feasibility evidence only; ts-mls is not selected for
production. Audit, secure persistence and human review remain open.

The [E02 assessment](../security/device-enrollment-review.md) records the
maintainer's 2026-11-12 product choices: one active logical device identity with
no hardware/non-copyability claim, and independent peer-key verification before
first send and after replacement. Credential design, client distribution and
independent crypto review remain open; these choices do not accept this ADR.
