# ADR 0004 Durable PostgreSQL state and transactional outbox

Status: Proposed
Date: 2026-11-12
Decision owner: AMDN maintainer and relevant architecture/security reviewers
Source: implementation plan sections 6, 7, 10, 15

## Context

An accepted message must survive API or broker failure without a database/broker dual-write gap.

## Proposed decision

Use PostgreSQL as the authority for ciphertext envelopes, participant-scoped inboxes, receipts, policy and delivery history. Commit the envelope and an outbox event atomically; return ACCEPTED only after commit. Publish asynchronously and record publication after broker confirmation. Use immutable transition history and a materialized current status.

## Alternatives and scope

Direct broker publication before durable storage and uncoordinated dual writes are rejected. A distributed transaction across database and broker is not proposed.

## Consequences

The relay can publish twice if it crashes after publication. Outbox cleanup, deduplication retention and backups must preserve recovery guarantees. Client time and declared sender identity are not trusted authorities.

## Acceptance evidence and open questions

Define table keys, uniqueness and tenant ownership; scope client idempotency to authenticated sender and payload identity. Decide retention and cleanup windows. Inject crashes around each commit and publication boundary.

Approval: Not recorded. Record reviewer, date and evidence before changing status.
