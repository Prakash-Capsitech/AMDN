# Provisioning and owner access

F1.3 exposes three deliberately small HTTPS operations. The services start with
these APIs disabled and no database credential. Migration 002 extends the F1.2
schema; migration 001 remains byte-for-byte unchanged. This implementation does
not approve the Proposed ADRs or close the F1 exit gate.

## Service boundaries and requests

| Service | Operation | Required token scope and database authority |
| --- | --- | --- |
| Provisioning | `POST /v1/tenants` | `tenant.provision` plus current platform grant |
| Provisioning | `POST /v1/tenants/{tenant_id}/memberships` | `membership.provision` plus current platform grant that created the tenant |
| Gateway | `GET /v1/postman?tenant_id=<uuid>` | `postman.read`, current membership and current owner grant for that postman |

The separate `src/Provisioning` executable receives only the provisioning login.
Gateway receives only the runtime login. Neither receives migration credentials.
Deploy provisioning as an operator-only service with its own OIDC audience and
network access policy. Configure the operator issuer/audience independently of the
Gateway's owner issuer/audience. Provider role claims, tenant ownership and token
scopes alone never establish a platform grant. No API can mint platform grants.

Tenant creation accepts only `{"display_name":"..."}` (1–100 characters).
Membership enrollment accepts only `{"issuer":"...","subject":"..."}`; issuer must
exactly match the configured owner issuer and subject is bounded to 255 characters.
The platform operator is responsible for verifying the enrollment target with that
provider; this is privileged enrollment, not email matching or self-registration.
The operator cannot choose local user/postman IDs, arbitrary capabilities or another
platform actor's tenant. Enrollment returns tenant/user/postman UUIDs. A tenant
owner receives its tenant UUID through the operator's onboarding channel.

Owner selection is explicit and stateless on every read, even for a single
membership. Only the canonical lowercase UUID query parameter is accepted. The
selection filters the authenticated `(issuer, subject)` lookup; it never creates
context by itself. Tenant headers confer no authority. No owner/user/postman ID
selector is accepted. Each read checks current tenant, user, membership, postman
and grant state within one transaction before returning the owner's public
postman projection and policy ETag. Foreign, unknown and revoked objects all return
404; missing operation scope returns 403 and invalid authentication returns 401.

The returned receive/dispatch/retry values are stored preferences, not permission
for a worker to execute an operation. Migration 002 defaults these preferences to
true, but only `postman.read` is seeded as an executable owner grant. Messaging,
device, policy-mutation, delegated worker and audit-query APIs remain
unimplemented. Their routes still return 404. See [enrollment administration](enrollment-administration.md)
for separate device-management grants. No content-access grant is created.

Requests reject unknown/duplicate properties, malformed UTF-8, compressed bodies,
invalid idempotency keys and bodies over 16 KiB. A supplied JSON charset must be
UTF-8, quoted or unquoted; duplicate charset parameters are rejected.
HTTPS is enforced at each API; there is no environment-based HTTP exception.
Configure Kestrel TLS or a separately
reviewed trusted proxy integration; the repository does not trust arbitrary
forwarded headers. Tests pin only their disposable TLS certificate. Responses use
no-store and generic problem details without SQL, tokens or internal errors.

## Atomic provisioning, grants and audit

A platform grant binds an immutable server-generated actor UUID to exact issuer
and subject, an expiry, a tenant quota and a version. An administrator creates or
revokes it with the migration-owner boundary after reviewing operator identity.
There are no built-in users, wildcard subjects or default platform grants. Revocation
is terminal. Transferring existing tenant administration to another actor is not an
API feature; it requires a separately reviewed administrative operation.

A tenant records its provisioning actor and explicit member limit. The actor row
lock serializes quota and replay decisions with grant changes. Tenant locks
serialize membership creation and count checks. Revoked memberships still count
toward the limit: revocation cannot reclaim identity capacity by recycling IDs.
The process-wide, actor and tenant request budgets below are additional limits.

Both commands require an Idempotency-Key of 16–128 visible ASCII characters. The
SHA-256 digest covers the operation, target tenant where applicable, and exact
request bytes. Concurrent identical retries return the same committed result;
different bytes or a different target with the same actor/operation/key return 409.
Every retry rechecks current platform authority and target lifecycle. Effect,
quota reservation, replay record and provisioning audit commit together. An audit
write failure rolls everything back and returns a generic retryable 503. No audit
entry is added for a replay because it creates no new provisioning effect.

Provisioning audit stores the actor UUID, resource UUIDs, operation, evaluated
grant version and server time. It contains neither raw request bodies nor tokens,
display names, signing material or ciphertext. API roles cannot update/delete audit
rows or delete replay keys. Successful mutations are durably audited; denied or
malformed requests do not create durable audit records in this slice. Operational
security-event logging, retention/export and denied-attempt monitoring remain
production work. No cleanup or replay-key expiry is enabled before A06 review.

Owner grants are fixed to `postman.read` on one tenant/postman. Existing active
F1.2 postmen receive that owner grant during upgrade; new enrollment seeds it in
the same transaction. Re-enrollment never restores an expired or revoked grant.
The narrow definer function locks the current grant while the scoped read completes,
serializing revocation with that read. Later operations must authorize again.
Grant lifecycle APIs are later policy work; privileged database tests exercise
expiry and revocation without pretending those APIs exist.

The process/credential trust boundary from the
[persistence guide](identity-persistence.md#database-authority) still applies.
A fully compromised provisioning credential can issue privileged SQL; it is not
contained by HTTP checks. Owner/runtime code never receives that credential.
Platform-grant administration and migrations remain a separate trusted boundary.

## Configuration and administration

Each service uses the existing `Authentication:Oidc` settings. The following
additional settings are required to opt in; connection strings belong in a secret
manager or protected environment, never committed configuration or CLI arguments.
All budget numbers are explicit deployment decisions; no production quota is
approved or inferred here. Missing, inconsistent or unknown settings fail startup.

| Setting | Owner Gateway | Provisioning service |
| --- | --- | --- |
| Section prefix | `IdentityApi` | `ProvisioningApi` |
| `Enabled` | true to expose owner route | true to expose provisioning routes |
| `ConnectionString` | restricted runtime login | separate provisioning login |
| `RequestsPerMinute` | endpoint-wide budget, 1–10000 | endpoint-wide budget, 1–10000 |
| `ActorRequestsPerMinute` | validated subject budget, at most endpoint budget | validated platform subject budget, at most endpoint budget |
| `TenantRequestsPerMinute` | verified tenant read budget, at most endpoint budget | must be zero/omitted |
| `TenantMemberLimit` | must be zero/omitted | explicit 1–10000 membership limit for newly created tenants |
| `OwnerIssuer` | must be empty/omitted | exact HTTPS issuer permitted for enrollment |

Request rate limits use process-local fixed windows without queuing. The owner
per-tenant budget is consumed only after membership/grant validation, so foreign
selectors cannot consume that tenant's partition. It limits successful read
responses; the actor and endpoint budgets bound attempted database reads. Health
and unmatched routes are excluded. Multi-instance/distributed rate enforcement,
load-calibrated values and production ingress protection remain pending A06/P01–P03.
Durable provisioning capacity quotas are database-enforced across instances.

Apply migrations explicitly with `IdentityMigrations.ApplyAsync` using the
migration login as described in the persistence guide. An administrator can then
use a reviewed, parameterized SQL operation under `amdn_identity_owner` to insert
`platform_grants(issuer, subject, expires_at, tenant_limit)`. Do not grant INSERT
on that table to either API role. The operator identity must be reviewed before
that write; this repository creates synthetic grants only inside disposable tests.
Use separate environment variables such as `IdentityApi__ConnectionString` and
`ProvisioningApi__ConnectionString` for their respective processes. No production
credential, platform grant or deployed service was created by this change.

## Evidence and pending gates

`make harness-test` applies the actual migrations and drives real Gateway and
Provisioning HTTPS listeners through signed tokens and PostgreSQL. It covers
concurrent replay, byte conflicts, exact membership selection, cross-tenant reads,
scope-only denial, grant expiry/revocation, quota races, audit failure rollback,
malformed bodies, restricted SQL roles, connection-role rejection and rate limits.
Existing F1.2 pool/restart and delivery-fixture cases remain enabled.

This supplies more P01 evidence for actual APIs, migrations, roles and pools.
[P01–P03](../../tests/Harness/README.md#evidence-and-scope) remain pending for full
application/worker/device/routing integration and production failure modes.
[Native N01/N02](agent-safety.md#pending-native-checks) remain pending. F1.4 device
enrollment still depends on E02 and identity review; no private key enrollment or
recovery scheme has been introduced. Dependabot #10 was separately evaluated and
closed without merging; see the
[compatibility evaluation](../../clients/crypto/README.md#pr-10-compatibility-evaluation).

Implementation references: [ASP.NET Core rate limiting](https://learn.microsoft.com/en-us/aspnet/core/performance/rate-limit?view=aspnetcore-10.0)
and [PostgreSQL row locks](https://www.postgresql.org/docs/18/explicit-locking.html).

See the harness's [recorded local validation](../../tests/Harness/README.md#recorded-local-validation)
for the run results and their limits. Hosted CI must validate each submitted head.
