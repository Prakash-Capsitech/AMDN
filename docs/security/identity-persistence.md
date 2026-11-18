# Tenant membership and personal postman persistence

F1.2 adds the application identity schema and persistence library.
[F1.3](provisioning-owner-access.md) adds the opt-in owner API and separate audited
provisioning service. This guide describes the lower-level storage boundary.
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
trusted provisioner; audited lifecycle APIs remain future work, not deployed features.

`PersonalPostmanStore.ReadAsync` accepts the principal produced by F1.1's token
validation. It rejects missing, duplicate, malformed or foreign-scheme subjects,
then looks up current active tenant, user, membership and postman rows. No identity
is auto-created on a read. Multiple memberships without selection fail closed.
A selected tenant only filters memberships already bound to the verified subject;
knowing a tenant UUID is insufficient. F1.3 exposes explicit per-request selection through the verified owner-read API.

Lookup takes shared row locks through the transaction so concurrent lifecycle
updates serialize with the read. This is a current-state snapshot, not a reusable
authorization grant: later operations must recheck current membership and their
own scopes, object grants and revocation conditions.

## Database authority

| Role | Authority |
| --- | --- |
| `amdn_identity_owner` | Non-login schema/migration owner; trusted definer functions |
| `amdn_identity_runtime` | Non-login group: scoped SELECT, narrow membership resolution and owner-grant checks |
| `amdn_identity_provisioner` | Non-login group: trusted cross-tenant SELECT/INSERT and status updates; no ID rebinding, delete, truncate or DDL |

The identity data and access-control tables have enabled and forced RLS. The owner
and provisioner have explicit policies for their privileged work; neither role is superuser or
BYPASSRLS. Runtime policies require transaction-local tenant, user, issuer and
subject values consistent with an active database membership. Missing, partial or
mismatched context returns no rows. Runtime cannot assume owner/provisioner roles.

The narrow `resolve_membership` security-definer function bridges an authenticated
external subject to local IDs before RLS context exists. It uses fixed SQL, a pinned
search path, no public execute grant, active-state checks and at most two results.
The RLS helper and owner-grant function likewise have pinned search paths and
explicit execute grants. See the [owner-grant boundary](provisioning-owner-access.md#atomic-provisioning-grants-and-audit)
for the additional authorization required by owner reads.
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
physical connection checks group membership, dangerous role attributes and relation
ownership within the identity schema. Both identity pools reject enrollment/executor
membership; a runtime pool also rejects provisioning/migration credentials. Transactions
set context locally, and disposal rolls back on denial, exceptions or cancellation.
Credential rotation or database privilege changes require pool replacement. Grant
management remains an administrator trust boundary, not continuous drift detection.

## Applying migrations

A database administrator reviews and runs
[roles.sql](../../src/Infrastructure/Identity/Migrations/roles.sql), then creates
separate secret-managed logins. Runtime/provisioner logins inherit only their
respective group and cannot SET ROLE to the owner. The migration login may SET ROLE
to the owner and is never given to the Gateway. Grant the owner CREATE on the target
database to create its schema, and CONNECT on that database to each login. Use authenticated encrypted database transport and
a least-privilege database ACL appropriate to deployment; no production connection
string or secret is supplied by this repository.

A trusted deployment host explicitly invokes `IdentityMigrations.ApplyAsync` with
the migration connection string. It takes an advisory transaction lock, assumes the
owner locally, and applies each pending embedded migration plus SHA-256 ledger entries in
one transaction. F1.3 adds migration 002, [device storage](device-persistence.md) adds 003, and
[ceremony transactions](ceremony-transactions.md) add 004. Migration 005 adds the
[enrollment execution boundary](enrollment-authority.md#pool-and-deployment); follow
that guide's administrator bootstrap and separate credential requirements before
applying it. Migration 006 adds [trusted enrollment administration](enrollment-administration.md).
Applied migrations remain unchanged. Reapplying the same version is a no-op; a changed applied checksum
fails. Later schema changes need new versioned migrations, not edits to applied SQL.
There is no automatic Gateway migration or deployment CLI. F1.3 adds explicit
provisioning APIs; production rollout remains pending.

The disposable harness bootstraps group membership and invokes this same migration
code before tests. Its [credential lifecycle](../../tests/Harness/README.md#lifecycle-credentials-and-failures)
owns the disposable login setup and administrator-password isolation.

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
Proposed ADRs, and crypto/contract review gates remain open. Dependabot #10 was
separately evaluated and closed without merging; see the
[compatibility evaluation](../../clients/crypto/README.md#pr-10-compatibility-evaluation).
Crypto pins are unchanged.
