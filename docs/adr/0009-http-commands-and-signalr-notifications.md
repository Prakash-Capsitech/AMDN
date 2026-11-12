# ADR 0009 HTTP commands and SignalR notifications

Status: Proposed
Date: 2026-11-12
Decision owner: AMDN maintainer and relevant architecture/security reviewers
Source: implementation plan sections 11, 13, 16

## Context

A live connection can drop at any time, so clients need a durable source for inboxes and message status.

## Proposed decision

Use HTTPS APIs for durable commands, status and synchronization; use SignalR over secure transport for online availability/status notifications. Propose ASP.NET Core for the backend and React/TypeScript for the eventual test client. Keep SignalR payloads minimal and derive connection tenant/user bindings from authenticated membership.

## Alternatives and scope

WebSocket-only state and transient notifications as the authoritative inbox are rejected. A production chat interface is not required for F0.

## Consequences

Clients reconcile gaps through authenticated HTTP APIs. SignalR scale-out, reconnect storms and connection quotas must be included in capacity planning. API errors and directory lookups must limit information leakage.

## Acceptance evidence and open questions

Finalize OpenAPI, OAuth scopes, error taxonomy, pagination, rate limits and envelope validation. Evaluate scale-out and sticky-session requirements before load testing. The scaffold exposes only process liveness.

Approval: Not recorded. Record reviewer, date and evidence before changing status.
