# AMDN

AMDN is an Agentic Message Delivery Network: each user has a logical personal
postman that delivers sealed messages through shared provider infrastructure.
The foundation must work without AI models.

This repository starts **F0 architecture and feasibility**. It contains proposed
ADRs, module boundaries, a buildable .NET backend scaffold, repository checks,
and a no-mistakes contribution workflow. It does not implement authentication,
message delivery, production encryption, persistence, a web client or deployment.
An isolated synthetic [MLS experiment](clients/crypto/README.md) runs in Node and
Chrome; it is not an application encryption adapter.

## Start locally

Prerequisites: the .NET SDK selected by global.json, Node from .nvmrc, Python 3.12 with venv support,
Git and GNU Make. Chrome is needed for the separate browser smoke check.
GitHub CLI and no-mistakes are needed to submit changes, not to build.

```sh
make setup
make crypto-restore
make contracts-restore
make verify
dotnet run --project src/Gateway --no-launch-profile --urls http://127.0.0.1:5080
# In another terminal:
curl --fail http://127.0.0.1:5080/health/live
```

The health response is process liveness only; it does not certify delivery readiness.
The separate worker host can be started with `dotnet run --project src/Workers`.
It has no delivery handlers yet.

## Repository map

| Path | Responsibility |
| --- | --- |
| src/Gateway | ASP.NET Core entry point and future SignalR connections |
| src/Identity | Tenant identity and policy boundary |
| src/Postman | Domain, runtime and delegated authorization |
| src/Messaging | Envelopes, delivery, receipts and transactional outbox |
| src/Infrastructure | Database, broker and telemetry adapters |
| src/Contracts | Shared reviewed contracts |
| src/Workers | Separate delivery and outbox process host |
| clients/web and clients/crypto | Reserved web client and isolated MLS feasibility experiment |
| tests | Integration, unit, isolation, reliability, performance and hook checks |
| deploy | Future local integration and deployment manifests |
| docs | Architecture, decisions, security, protocols and F0 acceptance |

Start with the [ADR register](docs/adr/README.md),
[architecture](docs/architecture/overview.md), and [F0 backlog](docs/plan/f0.md).
The [F0.4 contract draft](docs/protocols/README.md) adds identity, authorization,
OpenAPI and delivery-state proposals with executable consistency checks. It does
not expose new Gateway endpoints or close the architecture/crypto review gates.
The original [implementation plan](AMDN_Foundation_Phase_Implementation_Plan.docx)
is retained unchanged. [Source mapping](docs/plan/source-map.md) distinguishes
blueprint decisions from repository setup choices.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for feature branches, no-mistakes,
local hooks, CI checks and the current GitHub enforcement limitation.
For agent hooks and restricted file access, start with
[agent safety](docs/security/agent-safety.md). Review the
[threat model](docs/security/threat-model.md) and
[encryption feasibility evidence](docs/security/encryption-feasibility.md) before
fixing domain and wire contracts.

No open-source license is granted in this initial private repository. Licensing
is a maintainer decision before any public distribution.
