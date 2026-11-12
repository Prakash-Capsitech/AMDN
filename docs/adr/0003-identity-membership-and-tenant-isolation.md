# ADR 0003 Identity membership and tenant isolation

Status: Proposed
Date: 2026-11-12
Decision owner: AMDN maintainer and relevant architecture/security reviewers
Source: implementation plan sections 4, 9, 10, 14

## Context

Cross-tenant communication must not grant ordinary callers visibility into another tenant’s private records.

## Proposed decision

Authenticate using a standards-compliant OIDC provider. Derive tenant context from authenticated identity and verified active membership. Enforce authorization in trusted application code and PostgreSQL RLS with FORCE ROW LEVEL SECURITY. Use least-privileged application roles without superuser or BYPASSRLS and establish transaction-local tenant context. Workers independently validate job identity and current policy.

## Alternatives and scope

Client-supplied tenant context and a broad privileged delivery role are rejected. Separate databases per tenant remain a future operational alternative, not the proposed shared-table foundation.

## Consequences

Cross-tenant routing requires a narrow independently authorized interface that creates separate participant-side records. RLS is defense in depth; a tenant setting alone is not authenticated identity. Pool reuse and privileged migrations need explicit separation.

## Acceptance evidence and open questions

Choose the OIDC provider and map issuer/subject to tenant membership. Specify the router’s exact privileges and transaction boundaries. Negative tests must use production-equivalent roles and pooling.

Approval: Not recorded. Record reviewer, date and evidence before changing status.
