# F0.4 domain and API contracts

Status: Proposed review package. The ten blueprint endpoints, identity/data
constraints and delivery graph are drafted; no wire contract is frozen, ADR is
accepted, or messaging endpoint implemented. F0.3 E01–E06 and F0.4 A01–A07 remain
open. Native agent checks N01/N02 remain pending.

| Artifact | Review responsibility |
| --- | --- |
| [Identity and logical data model](identity-and-data.md) | Immutable IDs, membership, device/key lifecycle, table constraints and transaction boundaries |
| [Authorization matrix](authorization.md) | Endpoint and worker actions, resource grants, defaults and revocation |
| [HTTP/envelope contract](http-api.md) | OpenAPI semantics, limits, replay, errors, crypto dependencies and approval register |
| [OpenAPI 3.1.1 draft](openapi.json) | Ten proposed routes with strict request/response schemas and authorization requirements |
| [Delivery protocol](delivery.md) | Device-storage ack meaning, terminal states, expiry/ack races and reconnect |
| [State graph](delivery-state-machine.json) | Machine-readable proposed transitions, checked against status schemas |
| [Synthetic examples](examples/submit-message.json) | Non-production request data for schema review; not valid production cryptography |

The maintainer chose DEVICE_ACKED to mean durable sealed-record storage on the
authorized recipient device. Decryption is separate and READ is excluded.
The rest of this package remains a proposal awaiting design review.

Run `make contracts-restore contracts-test`. Standards validation, invalid input
fixtures and transition graph checks run under `make verify` as well. These checks
cannot establish authorization, RLS, database durability, broker delivery or device
storage. See the [F0.5 harness](../../tests/Harness/README.md) for separate
real-service fixture evidence and pending production integration.
`/v1/messages` continues to return 404 in the current scaffold.

The original [blueprint](../../AMDN_Foundation_Phase_Implementation_Plan.docx)
sections 4–11 and 17–20 are the source. See [traceability](../plan/source-map.md),
[threat model](../security/threat-model.md), and
[encryption gates](../security/encryption-feasibility.md#remaining-gates).
PR #10 remains deferred because ts-mls 1.6.4 requires curves 2.0.1; this work changes
no crypto dependency or native hook trust setting.
