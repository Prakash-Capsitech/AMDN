# ADR 0006 Delivery states acknowledgments and synchronization

Status: Proposed
Date: 2026-11-12
Decision owner: AMDN maintainer and relevant architecture/security reviewers
Source: implementation plan sections 6, 7, 11, 14

## Context

Server acceptance, inbox persistence and recipient receipt prove different things. Reordered or duplicated receipts must not create false delivery claims.

## Proposed decision

Use CREATED on the device, then ACCEPTED, QUEUED, INBOX_STORED and DEVICE_ACKED on the success path. Expose delivered only for DEVICE_ACKED. READ is excluded. Require an authenticated authorized recipient device to acknowledge the matching delivery. HTTP inbox synchronization reconstructs durable state after lost notifications. No global ordering is required; use server-assigned per-conversation sequencing where needed.

## Alternatives and scope

Broker acknowledgments and SignalR writes do not mean device delivery. Global total ordering and read receipts are deferred.

## Consequences

State transitions need conditional atomic updates; late events cannot regress success. Cursors must remain scoped to the recipient’s authorized view and not reveal another tenant’s history.

## Acceptance evidence and open questions

Finalize legal transitions, rejection/expiry/failure reasons and expiry-versus-ack races. Specify whether device acknowledgment follows local persistence or successful decryption; it is not yet decided. Define cursor retention, sequence allocation and duplicate acknowledgment behavior.

Approval: Not recorded. Record reviewer, date and evidence before changing status.
