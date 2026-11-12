# ADR 0005 JetStream asynchronous delivery and retries

Status: Proposed
Date: 2026-11-12
Decision owner: AMDN maintainer and relevant architecture/security reviewers
Source: implementation plan sections 7, 13, 15, 18

## Context

Offline recipients and transient failures require durable work processing independently of live connections.

## Proposed decision

Use NATS JetStream with durable consumers and at-least-once delivery. Consumers are idempotent; persist recipient inbox state before acknowledging successful processing. Use bounded attempts, backoff, expiry and per-tenant quotas. PostgreSQL remains authoritative and broker events contain minimum necessary routing information.

## Alternatives and scope

Exactly-once end-to-end delivery is not claimed. In-memory queues and notifications as the sole delivery channel are rejected.

## Consequences

Duplicate events and crashes are normal. Retryable attempts are events, not terminal failure. Poison jobs need an operator-visible terminal handling policy. Fair scheduling must prevent noisy tenants from starving others.

## Acceptance evidence and open questions

Define stream topology, replication, retention, ack deadlines, backoff, max attempts, dead-letter/quarantine handling and admission control. Test offline recovery, duplicate events and restart backlog drain.

Approval: Not recorded. Record reviewer, date and evidence before changing status.
