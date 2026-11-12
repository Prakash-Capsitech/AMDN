# ADR 0002 Logical postmen and modular execution

Status: Proposed
Date: 2026-11-12
Decision owner: AMDN maintainer and relevant architecture/security reviewers
Source: implementation plan sections 2, 3, 5, 16

## Context

One always-running process per user would couple registered identities to compute allocation and make recovery depend on process state.

## Proposed decision

Assign each user an immutable logical postman identity. Deploy Gateway, Identity, Postman and Messaging as one modular ASP.NET Core application. Run delivery and outbox work in a separate worker host using shared stateless execution. Keep authoritative state outside processes; invocations carry validated tenant, user, postman, invocation and policy context.

## Alternatives and scope

A process per postman and six independent microservices are deferred. Future handlers may add intelligence without replacing the durable delivery core.

## Consequences

Module boundaries must be enforced in code and contracts even while deployed together. Shared workers need quotas and context isolation; the scaffold does not yet implement either.

## Acceptance evidence and open questions

Approve module interfaces and lifecycle. Test crashes and concurrent users for context leakage. Benchmark before splitting services.

Approval: Not recorded. Record reviewer, date and evidence before changing status.
