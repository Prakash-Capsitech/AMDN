# Enrollment administration

Migration 006 adds trusted administrator SQL commands for WebAuthn configuration
and device-management grants, as a prerequisite for the opt-in enrollment HTTP
adapter. No public administration endpoint is added. See the
[HTTP guide](enrollment-http.md) for enrollment integration and its pending gates.

## Authority and deployment

Apply 006 through the existing explicit migration runner. Applied migrations
001–005 are unchanged; no new role or application privilege is needed. An operator
uses a separately controlled migration login and explicitly selects
`amdn_identity_owner`. Runtime, provisioning, enrollment and ceremony executor
roles cannot execute these commands or access their audit records. Functions are
SECURITY INVOKER with pinned `pg_catalog,pg_temp` search paths.

Use only a reviewed trusted operation, never an application host. This boundary
trusts the administrator: an owner can still issue raw SQL or change schema and
permissions. It does not audit every possible owner write or contain a compromised
administrator. Distinct database logins are needed for individual attribution;
operators sharing one login share an audit/replay identity.

## Commands

Each command requires a nonzero UUID key and a non-sensitive change/ticket
reference of 1–128 visible ASCII bytes. Pass typed parameters, never interpolate
request data into SQL. Use one command per transaction; commit before reporting
success. Rollback/failure leaves no effect or replay entry.

| Function in amdn_identity | Parameters after command UUID | Result |
| --- | --- | --- |
| `administer_device_configuration` | configuration UUID, expected version, RP ID, HTTPS origin, ACR array, maximum age seconds, enabled, reference | configuration UUID, version, enabled |
| `administer_device_grant` | tenant UUID, user UUID, postman UUID, action, expected version, expiry or NULL, reference | bound UUIDs, version, status |

Results include `outcome`: `ok`, `invalid_request`, `not_found` or `conflict`.
They are administrator SQL results, not enrollment wire DTOs. Storage failures
abort the transaction and are not successful outcomes.

### Configuration

Expected version zero creates, never overwrites. Updates require the exact
current version. Choose `enabled=false` while preparing deployment; enabling is
an explicit action, not credential-design approval. The RP/origin binding cannot
change in place through this command. A different binding requires a distinct
configuration and explicit deployment selection; existing devices are not migrated.

RP IDs and origins use lowercase ASCII DNS labels. Origins must be canonical HTTPS
without user info, path, query, fragment, trailing slash or explicit default port
443. Other ports are bounded to 1–65535. The host must equal the RP ID or be its
subdomain. Both RP IDs and origin hosts reject terminal decimal or hexadecimal
numeric labels under the [WHATWG URL Standard's ends-in-a-number rule](https://url.spec.whatwg.org/#ends-in-a-number-checker),
including hexadecimal, octal and shortened IPv4 spellings and malformed numeric
hosts. ACRs must be 1–16 distinct visible ASCII strings
of at most 256 bytes; maximum age is 1–900 seconds. These are not public-suffix-list
or browser qualification checks: the operator must review the registrable domain
and deployment binding.

Updates can change ACRs, maximum age and enabled state. The existing trigger
increments version only on actual changes. Existing ceremony checks invalidate
stale pending work. Disabling denies further commands, including old enrollment
replay disclosure. No-op updates retain version but audit their distinct command.

### Grants

`grant.issue` requires expected version zero, a finite future expiry and an active
tenant/user/membership/postman with the exact immutable ownership binding. It
creates only the existing `device.manage` grant; `postman.read` implies none of
this authority. Existing grants conflict. Renewal, deletion/recreation, expired
grant recovery and revoked-grant restoration are not operations in this slice.

`grant.revoke` requires the exact current version and NULL expiry. Revocation is
terminal and increments version. It remains available for suspended/revoked
identities: removing authority must not require an active identity. Unknown or
mismatched target bindings fail. Repeated revocation under a new key conflicts;
retry the original key to observe its result. Management-grant revocation does
not itself revoke a device or rewrite attribution. Existing ceremony functions
deny subsequent enrollment/proof commands after grant revocation.

Grant changes follow ceremony lock order: tenant, user, membership, postman, grant.
Expiry is checked after lock waits before issue effects. Configuration commands
lock only their configuration after command-key and configuration-create locks;
they never acquire a later identity lock.

## Replay and audit

`device_administration_audit` is both append-only command ledger and minimal audit.
Its key is actual database `session_user` plus command UUID, across administration
operations. A digest binds canonical typed inputs including action, target,
expected version, ordered ACRs and change reference. Grant expiry uses epoch time
so session timezone cannot change replay. This is not an HTTP byte-body digest.

Identical successful retries return the original historical result with no new
effect or row. Changed inputs or another action/target conflict. Historical results
are not current authority: replaying an issue after revocation returns its old
result without restoring the grant. Read current version/status before a new
command. Only successful commands reserve keys.

Effect and ledger insert share a transaction; audit failure rolls back both. The
record contains database operator, command/action, target IDs, versions, reference,
digest, result and server time. No bearer token, raw proof or private key is stored;
never put sensitive values in references. RLS is forced. UPDATE, DELETE and
TRUNCATE have retention guards. No cleanup is installed; privileged DDL and
external audit retention/export remain trusted operational responsibilities.

## Evidence and next work

`EnrollmentAdministrationTests` exercises actual SQL interfaces and disposable
PostgreSQL roles: atomic audit/replay, concurrent/stale commands, configuration
bounds and immutable bindings, application/executor denials, foreign targets,
inactive-identity revocation and expiry after lock waits. Actual execute-only
enrollment calls check that grant/configuration changes stop existing ceremony
use. Those calls use synthetic trusted service projections, not new signed
OIDC/WebAuthn or public HTTP evidence.

The [HTTP guide](enrollment-http.md#evidence-and-remaining-work) owns subsequent
endpoint integration evidence and its limits. Browser UX,
messaging-key binding, independent verification and deployment remain separate.
The [authority guide](enrollment-authority.md) owns the existing service trust boundary.
