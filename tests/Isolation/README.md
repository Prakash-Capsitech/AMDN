# Isolation

The [F0.5 harness](../Harness/README.md) exercises forced PostgreSQL RLS with a
non-owner/non-BYPASSRLS fixture login, two tenants and four users, same-connection
pool reuse after commit/rollback/error, missing context and forged job bindings.
Run `make harness-test`.

F1.2 additionally exercises the actual identity migrations, restricted runtime and
provisioning roles, size-one application pool, lifecycle denial and a real JWT
HTTP probe connected to the membership store. See the
[persistence evidence](../../docs/security/identity-persistence.md).

P01/P02 remain pending for deployed operation policies, owner APIs, device and
worker/broker integration. Passing this subset does not close the F1 exit gate. Native N01/N02
remain separately pending in [agent safety](../../docs/security/agent-safety.md).
