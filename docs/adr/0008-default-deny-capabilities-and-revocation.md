# ADR 0008 Default deny capabilities and revocation

Status: Proposed
Date: 2026-11-12
Decision owner: AMDN maintainer and relevant architecture/security reviewers
Source: implementation plan sections 5, 9, 11, 14

## Context

Possession of a postman identifier or queued job cannot confer authority. Policy must remain enforceable without an AI decision maker.

## Proposed decision

Use a central trusted policy evaluator. Allow only valid identity, valid scope, active grant, allowed resource and satisfied constraints. Seed explicitly defined owner/system permissions; deny undeclared actions. Authorize send, receive, dispatch, retry, device ack and policy modification independently. Postmen cannot read content or autonomously reply in the foundation. Record policy version and audit sensitive decisions.

## Alternatives and scope

An LLM as policy authority and client-only checks are rejected. Cedar/OPA is optional and not selected by the scaffold.

## Consequences

Revocation blocks future eligible delegated operations, but cannot retract content already received. Checking only at submission is insufficient for queued work. Receive-enabled defaults must coexist with explicit user blocking and default-deny unknown actions.

## Acceptance evidence and open questions

Finalize the action/resource matrix, seed grants, receive preferences and revocation boundary. Define worker rechecks and receipt authorization. Test revoked jobs, forged identities and unauthorized policy changes.

Approval: Not recorded. Record reviewer, date and evidence before changing status.
