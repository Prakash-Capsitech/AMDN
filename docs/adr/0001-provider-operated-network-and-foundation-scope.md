# ADR 0001 Provider operated network and foundation scope

Status: Proposed
Date: 2026-11-12
Decision owner: AMDN maintainer and relevant architecture/security reviewers
Source: implementation plan sections 1, 2, 15, 19

## Context

AMDN needs a reliable first network before autonomous behavior or federation can be evaluated.

## Proposed decision

Use one provider-operated environment and a single-region deployment with tested recovery. The foundation supports one-to-one messaging across at least two tenants, offline delivery and one active device per user. No AI model is required. Call the release Foundation and the work stages F0 through F6 to avoid overloading F1.

## Alternatives and scope

Cross-provider federation, per-user hosting and active-active regions are deferred. Group chat, attachments, autonomous replies, multi-device sync, MCP and A2A are outside this release.

## Consequences

The provider operates shared routing and sees metadata. Availability depends on the selected regional recovery design. The narrow scope does not imply production readiness.

## Acceptance evidence and open questions

Define hosting location, retention and recovery objectives. Demonstrate the Alice-to-Bob scenario with Bob offline; independently verify all five release gates.

Approval: Not recorded. Record reviewer, date and evidence before changing status.
