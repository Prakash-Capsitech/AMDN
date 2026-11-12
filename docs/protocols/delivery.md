# F0.4 delivery, acknowledgment and synchronization

Status: Proposed protocol. The maintainer selected durable device storage as the
acknowledgment meaning on 12 November 2026. Other transition/race details still
need design review; ADR 0006 remains Proposed.

## States and authority

`CREATED` is client-local. A rejected submission has no accepted envelope and
returns an HTTP problem; `REJECTED` is an attempt outcome, not a persisted delivery
state. The server states and permitted edges are in
[delivery-state-machine.json](delivery-state-machine.json).

| State | Evidence required |
| --- | --- |
| ACCEPTED | Sender envelope, idempotency result and outbox committed atomically |
| QUEUED | Broker confirmed publication; this is progress, not device receipt |
| INBOX_STORED | Independently authorized recipient inbox and event outbox committed |
| DEVICE_ACKED | Authorized addressed device claims it durably stored the sealed envelope; server receipt transaction committed |
| EXPIRED | Server expiry condition won the conditional transition before device ack |
| FAILED | Non-retryable policy/identity/routing failure or exhausted delivery budget before inbox storage |

Only DEVICE_ACKED yields `delivered: true`. It does **not** mean decrypted, read,
understood or backed up. A device may lie about its storage: this is an
authenticated claim, not remote attestation. Decryption happens separately and
cannot regress delivery status. READ and content-bearing error receipts are absent.

The recipient device must atomically persist the sealed record and its local
receipt intent before acknowledging. If that fails it must not ack. After a crash,
the client retries the same ack from its durable receipt intent. Local secure
storage and crash behavior remain E03; the current crypto spike does not implement
this device protocol. Device authorization/proof remains E02/F1 work.

## Progress and failure rules

Publish confirmation can arrive after recipient persistence, so ACCEPTED may
advance directly to INBOX_STORED. A late QUEUED update is ignored as stale; it must
not regress that state. Device receipts can also arrive at the sender projection
before the inbox event: park the later event and reconcile missing versions from
the authoritative recipient record, rather than inventing an unchecked transition.

Retryable transport failures append attempt history while preserving current
state; no extra public state is needed. Retry uses the original envelope/event
identity and bounded backoff. It must not exceed expiry or the configured attempt
budget. An explicit permanent failure is FAILED only before INBOX_STORED. After
inbox commit, provider retries/notifications cannot turn storage into FAILED.

All updates compare expected state/version inside the owning transaction and
append the new immutable event in that same commit. Deduplicate processed event
IDs with effects. Duplicates have no extra effect; conflicting reuses fail and are
audited. DEVICE_ACKED, EXPIRED and FAILED are terminal. Never publish success or
an HTTP 202 before its required database commit.

## Expiry and acknowledgment races

Use server UTC and the recipient delivery's immutable expires_at. The ack
transaction locks the delivery, checks device/membership authorization, and
obtains decision time **after** that lock. It may move INBOX_STORED to DEVICE_ACKED
only when decision time is strictly before expiry. At or after expiry it moves
to EXPIRED (if still eligible) and returns 409. An expiry worker uses the same
lock/conditional rule. A committed DEVICE_ACKED always remains successful.

A duplicate authorized ack of DEVICE_ACKED returns the original receipt even
after expiry; a different or revoked device still gets no authority. EXPIRED or
FAILED cannot be acknowledged. A stale/new-device request cannot mutate status.
Expiry stops network eligibility; it cannot erase ciphertext already fetched or
guarantee that a device has not decrypted it.

## Inbox synchronization

Notifications carry only event type, local resource ID and view version. They
are hints. Reconstruct inbox and sender status using authenticated HTTP after
disconnect; never acknowledge merely because a SignalR write succeeded.

The draft inbox returns retained INBOX_STORED and DEVICE_ACKED items for the
addressed device, excluding expired items from new fetches. A cursor is an opaque,
integrity-protected reference bound to tenant/user/device, filter and snapshot.
Changing any binding fails without exposing another view. Pagination must be based
on committed visibility: a preallocated database sequence is not a safe high-water
mark when an earlier transaction can commit later. Snapshot pages plus a committed
change feed must not skip such rows. Clients deduplicate by delivery ID/version.

A cursor outside retention returns 410 `cursor_expired`; the client starts a new
snapshot and reconciles retained IDs. No guarantee covers content beyond retention.
Status events may arrive out of order; versions and authoritative HTTP repair the
gap. Cursor encoding, retention, committed ordering and sequence allocation remain
A06 decisions and must be demonstrated by F0.5 concurrent-commit tests.

The JSON transition examples exercise a reference model only, not the Gateway,
PostgreSQL, broker or device storage. Native checks N01/N02 remain pending.
