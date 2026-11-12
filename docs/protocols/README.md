# Foundation contract backlog

Status: F0.4 draft ownership and decision checklist. No wire schema is frozen.

| Contract | Decisions to close |
| --- | --- |
| Identity | Immutable tenant/user/postman/device IDs, OIDC issuer and subject mapping, active membership, one active device |
| Envelope v1 | Versioning, limits, canonicalization, encoding, sender derivation, crypto binding, timestamps and expiry |
| Idempotency | Sender scope, request digest, same-key/different-payload conflict, retention, unique constraints |
| Delivery | Legal states, rejected/expired/failed outcomes, attempt events, retry ceilings and expiry races |
| Device ack | Authorized device binding, receipt meaning, persistence/decryption boundary, rekey, duplicate and late ack |
| Synchronization | Tenant/user cursors, paging, retention gaps, sequence allocation and out-of-order reconciliation |
| Routing | Narrow cross-tenant privileges, independently authorized participant records, policy race handling |
| API | OpenAPI schemas, auth scopes, authorization, error taxonomy and rate limits for every endpoint |
| Audit | Participant/operator visibility, immutable history, sensitive decision coverage, retention and redaction |

The blueprint proposes tenant/device registration, directory lookup, send, status,
inbox, acknowledgment, postman configuration, policy and audit APIs. None is
implemented by this scaffold. In particular, `/v1/messages` must not accept requests
until authentication and policy enforcement exist.

Foundation state vocabulary: CREATED (client), ACCEPTED (durable sender commit),
QUEUED, INBOX_STORED (durable recipient record), DEVICE_ACKED (authenticated device
confirmation). READ is excluded. Terminal failure branches and legal races must
be specified before implementation.
