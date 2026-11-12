# Architecture decision register

These drafts translate the 7 November 2026 implementation plan into reviewable
choices. They are proposals, not approved architecture or implementation claims.
Each decision records context, alternatives, consequences and required evidence.
Change status only after review; supersede accepted decisions with a new ADR.

| Decision | Status | Blueprint sections |
| --- | --- | --- |
| [0001 Provider operated network and foundation scope](0001-provider-operated-network-and-foundation-scope.md) | Proposed | 1, 2, 15, 19 |
| [0002 Logical postmen and modular execution](0002-logical-postmen-and-modular-execution.md) | Proposed | 2, 3, 5, 16 |
| [0003 Identity membership and tenant isolation](0003-identity-membership-and-tenant-isolation.md) | Proposed | 4, 9, 10, 14 |
| [0004 Durable PostgreSQL state and transactional outbox](0004-durable-postgresql-state-and-transactional-outbox.md) | Proposed | 6, 7, 10, 15 |
| [0005 JetStream asynchronous delivery and retries](0005-jetstream-asynchronous-delivery-and-retries.md) | Proposed | 7, 13, 15, 18 |
| [0006 Delivery states acknowledgments and synchronization](0006-delivery-states-acknowledgments-and-synchronization.md) | Proposed | 6, 7, 11, 14 |
| [0007 Client side encryption and single device trust](0007-client-side-encryption-and-single-device-trust.md) | Proposed | 2, 8, 18, 20 |
| [0008 Default deny capabilities and revocation](0008-default-deny-capabilities-and-revocation.md) | Proposed | 5, 9, 11, 14 |
| [0009 HTTP commands and SignalR notifications](0009-http-commands-and-signalr-notifications.md) | Proposed | 11, 13, 16 |
| [0010 Evidence based release and operations](0010-evidence-based-release-and-operations.md) | Proposed | 12, 13, 14, 17, 19, 20 |
| [0011 WebAuthn enrollment credentials](0011-webauthn-enrollment-credentials.md) | Proposed | F1.4 / E02 follow-up |

F0.1 acceptance requires review of this register and resolution or explicitly
owned deferral of open decisions. Crypto protocol selection requires F0.3 evidence.
See [F0 work packages](../plan/f0.md) and the [source map](../plan/source-map.md).
