# ADR 0010 Evidence based release and operations

Status: Proposed
Date: 2026-11-12
Decision owner: AMDN maintainer and relevant architecture/security reviewers
Source: implementation plan sections 12, 13, 14, 17, 19, 20

## Context

A successful chat demonstration does not prove reliable, private multi-tenant delivery.

## Proposed decision

Gate release on isolation, reviewed client E2EE, durable accepted-message recovery, correct authorization/revocation and measured performance plus recovery. Collect OpenTelemetry diagnostics without secrets/plaintext. Use xUnit and future Testcontainers scenarios, k6 load tests and operational restore exercises. Keep local checks and CI automated and route contributions through no-mistakes PRs.

## Alternatives and scope

Screenshots or scaffold tests alone cannot satisfy release gates. Kubernetes and active-active regions are not assumed. The no-mistakes guardrail does not replace security review.

## Consequences

Proposed validation targets: 10,000 registered users, 1,000 concurrent connections, 100 submissions/second for five minutes, p95 acceptance 250 ms and healthy-network p95 online delivery below one second. These are not measured results or availability guarantees.

## Acceptance evidence and open questions

Define message sizes, hardware, recovery point/time objectives, retention, quotas, alert thresholds and owners. Capture reproducible failure-injection and load evidence. F0 is complete only after its five work packages have reviewed evidence.

Approval: Not recorded. Record reviewer, date and evidence before changing status.
