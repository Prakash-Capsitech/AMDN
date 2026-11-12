# Isolation

The [F0.5 harness](../Harness/README.md) exercises forced PostgreSQL RLS with a
non-owner/non-BYPASSRLS fixture login, two tenants and four users, same-connection
pool reuse after commit/rollback/error, missing context and forged job bindings.
Run `make harness-test`.

Actual application role/pool parity and authenticated caller/broker binding remain
pending (P01/P02): production identity and persistence adapters do not exist yet.
Passing fixture tests is not production tenant-isolation evidence. Native N01/N02
remain separately pending in [agent safety](../../docs/security/agent-safety.md).
