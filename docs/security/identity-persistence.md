# Tenant membership and personal postman persistence

F1.2 adds the application identity schema and persistence library. The Gateway
still exposes no tenant, provisioning or postman API. F1.3 must add audited
provisioning and operation authorization before exposing this library to callers.
Do not use the authentication-only policy as permission to access tenant data.

## Identity and lifecycle

The trusted provisioning primitive creates database-generated tenant/user/postman
UUIDs. Membership binds the exact, case-sensitive external `(issuer, subject)` to
one local user in a tenant. Email, provider roles and provider tenant IDs confer
no authority. The same external identity in two tenants receives separate local
user and postman IDs. There is at most one primary personal postman per local user;
the provisioner creates user, membership and postman atomically. A composite
foreign key prevents attaching a postman to a user in another tenant.

Repeated and concurrent enrollment returns the existing identity. A tenant row
lock serializes this low-volume provisioning path. Registration never silently
reactivates suspended or revoked records. IDs and external identity bindings are
immutable; status changes increment user identity, membership or postman policy
versions. Revocation is terminal. Suspension can be reversed by the separately
trusted provisioner; audited lifecycle APIs are F1.3 work, not deployed features.

`PersonalPostmanStore.ReadAsync` accepts the principal produced by F1.1's token
validation. It rejects missing, duplicate, malformed or foreign-scheme subjects,
then looks up current active tenant, user, membership and postman rows. No identity
is auto-created on a read. Multiple memberships without selection fail closed.
A selected tenant only filters memberships already bound to the verified subject;
knowing a tenant UUID is insufficient. UI/API membership selection is still F1.3.

Lookup takes shared row locks through the transaction so concurrent lifecycle
updates serialize with the read. This is a current-state snapshot, not a reusable
authorization grant: later operations must recheck current membership and their
own scopes, object grants and revocation conditions.

## Database authority

| Role | Authority |
| --- | --- |
| `amdn_identity_owner` | Non-login schema/migration owner; trusted definer functions |
| `amdn_identity_runtime` | Non-login group: scoped SELECT and narrow membership resolution only |
| `amdn_identity_provisioner` | Non-login group: trusted cross-tenant SELECT/INSERT and status updates; no ID rebinding, delete, truncate or DDL |

All four identity tables have enabled and forced RLS. The owner and provisioner
have explicit policies for their privileged work; neither role is superuser or
BYPASSRLS. Runtime policies require transaction-local tenant, user, issuer and
subject values consistent with an active database membership. Missing, partial or
mismatched context returns no rows. Runtime cannot assume owner/provisioner roles.

The narrow `resolve_membership` security-definer function bridges an authenticated
external subject to local IDs before RLS context exists. It uses fixed SQL, a pinned
search path, no public execute grant, active-state checks and at most two results.
The RLS helper likewise has a pinned search path and explicit execute grants.
The owner policy prevents recursion while the helper examines membership.

**The service process and runtime credential are a trust boundary.** A caller
with arbitrary SQL execution using that credential can invoke lookup with another
subject and set custom PostgreSQL settings. RLS is defense against missing or
incorrect application scoping, not containment of a fully compromised application
credential. Public requests must never supply a principal, SQL or context directly.
Tests that construct principals directly are synthetic inputs; a separate live
HTTP test traverses real JWT validation before the actual persistence adapter.

`IdentityDatabase` creates bounded Npgsql pools with reset-on-close, no multiplexing
or ambient transaction enlistment, and no parameter/error-detail logging. Each new
physical connection checks group membership, dangerous role attributes and schema
ownership; a runtime pool rejects provisioning/migration credentials. Transactions
set context locally, and disposal rolls back on denial, exceptions or cancellation.
Credential rotation or database privilege changes require pool replacement. Grant
management remains an administrator trust boundary, not continuous drift detection.

## Applying migrations

A database administrator reviews and runs
[roles.sql](../../src/Infrastructure/Identity/Migrations/roles.sql) once, then creates
separate secret-managed logins. Runtime/provisioner logins inherit only their
respective group and cannot SET ROLE to the owner. The migration login may SET ROLE
to the owner and is never given to the Gateway. Grant the owner CREATE on the target
database to create its schema, and CONNECT on that database to each login. Use authenticated encrypted database transport and
a least-privilege database ACL appropriate to deployment; no production connection
string or secret is supplied by this repository.

A trusted deployment host explicitly invokes `IdentityMigrations.ApplyAsync` with
the migration connection string. It takes an advisory transaction lock, assumes the
owner locally, and applies embedded migration 001 plus a SHA-256 ledger entry in
one transaction. Reapplying the same version is a no-op; a changed applied checksum
fails. Later schema changes need new versioned migrations, not edits to applied SQL.
There is no automatic Gateway migration, provisioner registration, deployment CLI
or production rollout in this slice.

The disposable harness creates all three separate logins with generated secrets,
bootstraps group membership, and invokes this same migration code before tests.
It never passes the PostgreSQL administrator password to the .NET tests.

## Evidence and remaining work

`make harness-test` exercises actual migrations, role grants, persistence methods
and a size-one application pool against pinned PostgreSQL. Cases cover concurrent
registration, tenant-local IDs, uniqueness/composite foreign keys, immutable IDs,
wrong-role rejection, absent/partial/mismatched RLS context, reused connections,
rollback, SQL error, cancellation, lifecycle denial and database process restart.
The HTTP case uses a disposable HTTPS issuer and a test-only Gateway route, verifies
current membership, and rejects invalid tokens and foreign tenant selection.
It is not a deployed operation policy or owner API.

[Production checks P01–P03](../../tests/Harness/README.md#evidence-and-scope) remain
pending: F1.2 supplies a subset of P01 identity persistence evidence, not application
API/worker/routing integration, device revocation, multi-node failover or recovery
objectives. [Native N01/N02](agent-safety.md#pending-native-checks), F0 approvals,
Proposed ADRs, and crypto/contract review gates remain open. Dependabot #10 remains
deferred and crypto pins are unchanged.
