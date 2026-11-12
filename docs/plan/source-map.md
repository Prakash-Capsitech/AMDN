# Blueprint traceability

Primary source: [AMDN Foundation Phase Implementation Plan](../../AMDN_Foundation_Phase_Implementation_Plan.docx),
version 1.0, planning baseline 7 November 2026. The source is preserved unchanged.

| Blueprint | Repository interpretation |
| --- | --- |
| Sections 1-5 | ADRs 0001-0003 and module/deployment boundaries |
| Sections 6-7 and 10-11 | ADRs 0004-0006, 0009 and contract backlog |
| Section 8 | ADR 0007 and encryption feasibility plan |
| Section 9 | ADR 0008 and authorization review items |
| Sections 12-15 and 17-20 | ADR 0010, threat inventory and F0 backlog |
| Section 16 | src, clients, tests, deploy and docs layout |

Repository-specific setup choices: .NET 10 with an SDK feature-band pin, one
solution, a process-liveness endpoint, empty module assemblies, a worker host,
bootstrap integration tests, versioned Git hooks, private GitHub hosting and
no-mistakes PR checks. These enable development; they are not blueprint claims
that a working delivery kernel already exists.

The F0 request asks for project structure and drafted decisions. Remaining F0
experiments and approvals are explicitly pending. No production encryption,
provider, database schema, wire contract or deployment is selected by placeholder
folders. The React client is reserved until crypto feasibility informs its setup.
