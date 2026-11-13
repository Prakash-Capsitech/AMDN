# F0.4 identity and logical data model

Status: Proposed design, not a migration or implemented authorization system.
Source: blueprint sections 4, 5, 10 and 11; ADRs 0003, 0004 and 0008.
Review alongside [authorization](authorization.md) and [HTTP contracts](http-api.md).

## Identity rules

Use immutable, server-generated UUIDs for tenant, user, postman, device, key,
envelope and delivery identities. The draft wire representation is lowercase
hyphenated UUID text; emails and delivery addresses are mutable aliases, never
primary keys. Client message and conversation correlation IDs are client-generated
UUIDs; knowing or choosing one grants no access. IDs are never reused after deletion.

A user record belongs to a tenant. A validated OIDC `(issuer, subject)` maps to
membership in that tenant; the same external subject in another tenant has a
different local user identity. Validate issuer, audience, signature, lifetime and
active membership. A session selects one verified membership. Caller-provided
tenant headers, route fields and job labels cannot establish this context.
OIDC provider selection and enrollment remain F1 prerequisites, not this draft's
implementation. Operator provisioning uses a separate platform identity.

Each active user has one primary logical postman and at most one active logical
device identity. The maintainer selected this server-side invariant without a
hardware-binding or key non-copyability guarantee in the [E02 review](../security/device-enrollment-review.md).
The [WebAuthn credential design](../security/enrollment-credential-design.md)
owns staged enrollment, replacement, revocation and credential-only activation
requirements. Public key records are immutable; private keys never enter the
provider.

Replacement does not recover old ciphertext or move old deliveries to a new key.
Clients must independently verify the first-contact binding before sending any
message, and verify each replacement before creating a fresh sending session. A
directory lookup is an authenticated public-key claim, not independent proof of
first-contact identity. E01–E06 remain open.

## Logical schema and ownership

This is a proposed constraint inventory, not a description of the implemented schema.
See the [identity persistence guide](../security/identity-persistence.md) for the
implemented subset and its migration. `T` denotes
the owning tenant; participant records have their own tenant context. Every
tenant-owned reference uses a composite tenant key, not a bare cross-tenant FK.
Lifecycle/event timestamps are server-assigned. Submitted message timestamps
follow the [HTTP envelope rules](http-api.md); they are not evidence of server
admission or delivery time.

| Record | Key / uniqueness | Essential columns and constraints |
| --- | --- | --- |
| tenants | tenant_id | status, limits_version; platform provisioning only |
| users | (T, user_id) | status, identity_version; local identity cannot move tenant |
| tenant_memberships | (T, issuer, subject), unique (T, user_id) | role, status, membership_version; no email matching |
| postman_principals | (T, postman_id), unique active (T, owner_user_id) | owner, state, policy_version; logical identity, no private runtime state |
| devices | (T, device_id), unique active (T, user_id) | owner, identity_version, status, enrolled_at, revoked_at |
| identity_key_records | (T, key_id) | device FK, profile, immutable public bytes, version, revoked_at; no private material |
| communication_addresses | normalized address | narrow directory projection of postman/device/key IDs; verification and lifecycle version; no inbox/history read |
| conversations | (T, conversation_view_id) | local owner and client correlation UUID; not a global authorization key |
| conversation_participants | (T, conversation_view_id, participant_ref) | locally authorized participant projection; no remote private-history FK |
| envelopes | (sender_T, envelope_id); unique (sender_T, sender_user_id, client_message_id) | immutable sender/device/key binding, recipient snapshot, ciphertext/profile, accepted_at, expires_at |
| command_idempotency | (T, actor_user_id, operation, idempotency_key) | request_digest, result identity/status, expires_at; committed with command effects |
| inbox_deliveries | (recipient_T, delivery_id); unique (recipient_T, recipient_user_id, envelope_id) | immutable addressed device/key, local ciphertext copy, expiry, current state/version |
| message_receipts | (T, receipt_id); unique (T, delivery_id, receipt_kind) | authenticated actor/device, server received_at; append-only; separately scoped sender projection |
| delivery_events | (T, delivery_id, state_version) | from/to state, reason, invocation/event ID, server time; immutable history plus conditional current-state update |
| outbox_events | (T, event_id) | aggregate reference/version, minimal routing fields, publication status/attempt; committed with source state |
| processed_events | (consumer, T, event_id) | result reference, processed_at; unique with consumer-side effects in the same transaction |
| postman_grants | (T, grant_id) | owner/postman, action, resource scope, constraints, expiry, version, revocation; unknown actions denied |
| audit_events | (T, audit_id) | actor, action, resource, outcome, policy_version, server time; no ciphertext, tokens or private keys |

Address normalization and reassignment quarantine are unresolved A02 decisions.
An address is resolved at admission to an immutable recipient identity/key
snapshot. Dispatch must never re-resolve an old address to a new owner.
The API includes expected recipient key/device IDs to reject stale directory data.

## Transaction and privilege boundaries

The sender transaction authenticates and authorizes, reserves idempotency,
inserts envelope plus ACCEPTED event and outbox, and commits before returning 202.
A retry gets the persisted result, including after a lost response. A unique
constraint arbitrates simultaneous duplicates. No broker call is part of this
transaction, and a broker failure cannot undo an accepted envelope.

The router consumes a validated event and a server-issued envelope reference.
It may obtain only the sealed routing projection needed for that delivery. It
cannot enumerate users, read inboxes, accept arbitrary SQL or select private
conversation histories. A narrow recipient operation rechecks current policy,
membership, addressed device/key and expiry, then atomically commits the inbox,
deduplication record and receipt/event outbox under the recipient's boundary.
Sender-visible progress is a separately authorized, idempotent projection of
those events; it may lag. There is no cross-tenant distributed transaction.

Every ordinary transaction uses a non-owner, non-superuser, non-BYPASSRLS role
with FORCE RLS and transaction-local context established by trusted code. Context
values alone are not credentials. The router interface must not confer arbitrary
tenant switching to general application callers. Migration/backup identities are
separate. Routing SQL roles, policy predicates and narrow-function implementation
remain A03/F0.5 work; this proposed model is not runtime RLS evidence.

Retention must preserve idempotency and processed-event records through the
maximum retry/redelivery window. A06 must set these windows before cleanup can be
enabled; deleting a deduplication record must not resurrect an old command.

## Required evidence

F0.5 must test forged tenant references, duplicate constraints, concurrent device
replacement, stale key/address snapshots, row-policy denial with actual pooled
application roles, and crashes around each commit/publication boundary. Schema
validation in this PR proves none of those runtime properties.
