# Validated enrollment principals and execution roles

F1.4 now connects validated OIDC evidence to the verifier/transaction bridge and
adds an execute-only application credential boundary in migration 005. **Live
enrollment remains pending.** No Gateway, Provisioning or Worker registration,
production credential, enrollment route, grant/configuration administration API
or browser adapter is enabled. The harness uses disposable roles and test-only
HTTPS probes; its operations are not deployed public endpoints.

## Principal mapping

After the existing issuer, audience, signature, lifetime and typed-payload checks
succeed, `IdentityAuthentication` puts an immutable `ValidatedAccessToken` in the
authentication result's in-process parameters. Its constructor is internal to
Identity. It carries issuer, subject, client ID, scopes, ACR, auth_time and expiry;
it retains no bearer token. It is not serialized into a token or cookie and is not
a new cryptographic credential.

`EnrollmentPrincipalMapper.FromRequestAsync` explicitly authenticates the AMDN
OIDC scheme and requires that validation evidence. It ignores `HttpContext.User`,
including replacement or mutation of its claims. A principal constructed merely
with an authenticated-looking identity, issuer/subject or device.manage claim
cannot produce the evidence. Trusted middleware and authentication services are
still within the application's trust boundary; this is not isolation against
arbitrary code running inside that process.

Mapping requires enabled step-up, exact device.manage scope, an allowed ACR,
nonfuture recent auth_time and strictly unexpired token. Token clock-skew grace
does not extend enrollment authority. The bound deadline is the earlier of token
expiry and the configured step-up deadline, so retaining a mapped principal cannot
extend its age. SQL further applies the current grant and RP configuration limits.
Issuer/subject/client are bounded to 2,048/255/256 UTF-8 bytes and exclude NUL.

The tenant UUID is a **selection filter**, not authority. No tenant/user/device
claim, arbitrary tenant header or external subject-to-user guess becomes local
identity. Each SQL call resolves the signed issuer/subject within the selected
active membership. Only then is transaction-local tenant/user/issuer/subject
context established; ordinary authorization rechecks and locks follow. Missing or
foreign membership fails closed. Configuration UUID and canonical HTTPS origin
come from an explicit immutable deployment binding, never Host, Origin or forwarded
headers. A future HTTP adapter must separately enforce the request Origin policy.

The public `EnrollmentCommands` accepts only a non-publicly-constructible
`EnrollmentPrincipal`. Raw `CeremonyActor` and `CeremonyVerifier` are now internal;
the harness is a friend assembly for synthetic lower-layer tests. The public facade
provides begin and proof completion, generating begin challenges/handles with the
platform RNG. Begin's typed operation/version/target parameters are trusted adapter
inputs; the future HTTP parser must derive them consistently from the exact bounded
request bytes. This facade does not implement the complete wire contract.

## PostgreSQL roles and RLS

| Principal | Authority |
| --- | --- |
| amdn_identity_enrollment | Non-login group; schema/type usage and EXECUTE on exactly four entry functions; no identity table/column read or write |
| Dedicated enrollment login | Inherits only the enrollment group; no owner, executor, runtime or provisioner membership |
| amdn_identity_ceremony_executor | Non-login, non-owner, non-BYPASSRLS definer role; owns the entry functions and has explicit scoped table/column/helper privileges |
| amdn_identity_owner | Existing trusted migration owner; applies schema/privilege changes and owns the narrow context bootstrap lookup |

The only application entry functions are `amdn_enrollment.begin`, `reserve`,
`finish` and `fail`. They are SECURITY DEFINER, owned by the executor, with a pinned
`pg_catalog,pg_temp` search path and qualified table/function references. PUBLIC
execute and schema creation are absent. Runtime/provisioner roles gain no entry
access. The application cannot call core ceremony helpers, snapshots, the context
lookup or membership resolver, and cannot assume the executor/owner roles.

A private owner-defined `enrollment_context` clears prior local context and resolves
only the supplied issuer/subject/tenant's active membership. Only the executor may
call it. This fixed narrow owner-policy lookup is needed before scoped RLS can
identify a user; it performs no mutation, grants no caller table access and takes
no extra row locks that would invert the existing ceremony lock order. Core
authorization then rechecks current membership, postman, grants, configuration,
scope, freshness and lifecycle versions under the established locks.

The executor itself is neither a table owner nor a member of the owner/provisioner
roles. Forced RLS remains enabled. Its policies use active membership plus exact
transaction-local tenant/user identity. Child challenge/audit rows require a visible
owned ceremony; configuration reads are confined to the selected configuration.
No grant/configuration mutation, DELETE, TRUNCATE or schema creation is granted.
PostgreSQL row-locking SELECT requires UPDATE privilege on at least one column;
for authority rows the executor receives only immutable identity-column UPDATE
privileges for locking, never status/expiry/configuration-policy mutation. Existing
triggers retain identities. Device/ceremony writes are explicitly column-scoped.
The user trigger permits the executor an increment of exactly one, under scoped
RLS, to preserve atomic lifecycle effects. Prior migrations 001–004 are unchanged.

The execution credential represents a **trusted service**, not an end-user session.
SQL cannot independently validate JWT signatures or WebAuthn proofs: a compromised
service credential can invoke the allowed functions with fabricated actor/proof
projections. Principal mapping and the verifier are mandatory parts of that trust
boundary. Execute-only permissions reduce accidental/general SQL access; they do
not make a compromised service or database administrator trustworthy.

## Pool and deployment

`EnrollmentDatabase.Pool` uses bounded pooling, connection reset, no multiplexing,
no ambient enlistment, no startup Options, and no detailed/parameter logging. Each
new physical connection checks role separation and dangerous attributes, expected
function ownership/execution, absence of table/column privileges, and absence of
schema CREATE or core helper execution. Mixed or overprivileged credentials fail
closed. This is a connection-creation guard, not continuous monitoring of an
administrator's permission changes; replace pools when changing grants.

Reservation commits and connection disposal still precede verification. Finish or
failure uses a separate transaction. The new reserve entry returns the next-stage
decision with its locked snapshot, removing the verifier's direct operation-table
read. SQL still rechecks actor and deadlines after waits. Context is transaction
local and pool reset remains enabled; an error, rollback or reused connection must
not carry another actor's context into the next command.

Deployment remains explicit: an administrator first reruns the reviewed
`roles.sql` bootstrap, then the separate migration runner applies 005 under the
existing checksum/advisory-lock ledger. No application startup creates roles or
runs migrations. The bootstrap gives only the migration owner SET membership in
the executor for atomic function ownership transfer, without inheritance. CREATE
on the entry schema is temporarily granted for that transfer and revoked within
the migration transaction. Never grant this membership to an application login.

Provision a distinct non-superuser, non-BYPASSRLS login through the administrator's
secret-management process. Grant only `amdn_identity_enrollment` with INHERIT TRUE
and SET FALSE. Do not reuse runtime, provisioning or migration credentials. No
login or password is installed by repository SQL; harness credentials are generated
for disposable services and removed at teardown. Explicit device.manage grants
and enabled RP configuration still require administrator setup; postman.read never
implicitly grants enrollment authority.

## Evidence and remaining checks

The harness uses signed access tokens, real HTTPS discovery/JWKS, actual WebAuthn
signatures, separate PostgreSQL credentials and a one-connection pool. It exercises
successful enrollment, foreign actors/tenant selections, changed client binding,
claim replacement/mutation, missing or stale step-up, token expiry within OIDC skew,
grant/membership revocation, context cleanup, direct SQL/helper/role denials, scoped
executor RLS and rejection of overprivileged pools. Existing verifier and transaction
tests continue through the new entry boundary. Synthetic lower-layer cases retain
their separate migration-owner fixture setup.

These are internal integration and test-probe results. Live enrollment still needs
the production endpoint/DTO/transport/error/budget integration, audited grant and
configuration administration, browser/client UX, deployment and independent review.
Messaging-key binding and independent peer verification remain separate. ADRs and
E02 approvals remain open. [Native N01/N02](agent-safety.md#pending-native-checks),
full [production P01–P03](../../tests/Harness/README.md#evidence-and-scope) and live
enrollment remain pending. Dependabot #10 stays deferred; hooks and PR/CI gates are
unchanged.

References: [PostgreSQL SECURITY DEFINER guidance](https://www.postgresql.org/docs/18/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY),
[row security](https://www.postgresql.org/docs/18/ddl-rowsecurity.html) and
[authentication result parameters](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationproperties.setparameter?view=aspnetcore-10.0).
