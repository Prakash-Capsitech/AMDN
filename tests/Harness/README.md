# PostgreSQL and JetStream harness

Run `make harness-test` from the repository root with the
[prerequisites](../../README.md#start-locally). The default Docker context must
use a local Unix socket. The runner needs
permission to create disposable containers; it does not alter Docker permissions
or agent sandboxes. A missing prerequisite fails the command, never skips tests.

The runner restores locked NuGet dependencies, builds and verifies formatting of
the standalone test project, then runs xUnit against real PostgreSQL and NATS
with JetStream file storage. [compose.yaml](compose.yaml) owns the image versions
and OCI digest pins. This project
is deliberately outside AMDN.sln so `make verify` stays usable without Docker;
the separate **PostgreSQL and JetStream harness** CI job is required by the merge
procedure. It has read-only GitHub permissions and no persisted checkout credentials.

## Evidence and scope

All users, messages and keys are synthetic. The fixture contains two tenants and
two users per tenant. SQL creates an owner without login and an application login
without ownership, superuser, role creation or BYPASSRLS. All five scoped tables
have forced RLS and transaction-local tenant/user context. Tests use that login
and an Npgsql pool limited to one physical connection, including concurrent callers.

| Scenario | Assertion |
| --- | --- |
| Role boundary | Non-owner/non-BYPASSRLS login, forced policies, owner assumption and truncate denied |
| Tenant and user isolation | Each of four users sees only itself; foreign tenant/user writes and missing/partial context fail closed |
| Pool reuse | Same backend PID reused after commit, rollback and SQL error; no stale tenant/user context |
| Writer killed before/after commit | Envelope and outbox both absent or both durable |
| Publisher killed after PubAck | Unmarked outbox replays two distinct broker messages with one inbox effect |
| Consumer killed after inbox commit | Durable consumer redelivers; processed event and inbox stay unique; broker ACK leaves device acknowledgment false |
| Forged job | Fixture trusted sender and stored event/envelope/recipient binding reject changed claims |
| Offline recipient and service restart | SIGKILL/restart of PostgreSQL and NATS preserves committed envelope/outbox and file-stream backlog; later consumption restores identical opaque bytes |

Crash probes are separate processes killed after explicit checkpoints; they cannot
run graceful disposal handlers. Container restarts check the exact run ownership
label before sending SIGKILL. Tests are sequential so service restarts cannot race
other scenarios. Assertions fail on timeout. There are no environment-based skips.

**The delivery fixture is a test model, not production delivery code.**
Gateway identity endpoints are tested separately by the F1.3 cases. The fixture's trusted principals and cross-tenant dispatch
are test inputs, not authentication, authorization or a reviewed routing privilege
design. Its opaque byte array is not encryption evidence. A caller able to issue
arbitrary SQL with the fixture login can set its own context; production must bind
context to authenticated membership before granting access to these operations.

F1.2 adds [actual identity persistence tests](../../docs/security/identity-persistence.md)
in addition to this delivery model. They apply the embedded application migration,
use separate migration/provisioning/runtime roles, and exercise registration,
identity constraints, lifecycle changes, RLS and the actual Npgsql pool. The
size-one pool is reused after success, denial, rollback, SQL error and cancellation.
A disposable HTTPS issuer and test-only Gateway route connect validated tokens to
current database membership. Database process restart checks committed identities.
These tests use generated synthetic identities and do not deploy a public API.

F1.3 adds [real provisioning and owner API tests](../../docs/security/provisioning-owner-access.md)
over HTTPS, using the separate application hosts and their actual credentials.
They exercise grants, scope/selection checks, replay, concurrent quotas, strict
commands, atomic audit rollback, rate limits and revocation ordering. Error bodies
and required headers are checked against the published OpenAPI problem constraints,
including status-specific codes and canonical server-generated request IDs. Both hosts
remain disabled by default; these tests do not create a deployed service.

The following acceptance evidence remains pending:

- **P01:** run these cases through the actual application roles, pool configuration,
  migrations, authenticated API and worker adapters when F1-F3 implement them.
  F1.2 now covers the actual identity store/migrations/roles/pool and a test-only
  authenticated HTTP probe. F1.3 adds actual provisioning and owner-read API tests.
  Device, worker/routing, deployment and complete production integration remain
  pending. P01 is not complete.
- **P02:** forged broker provenance, device ownership/revocation, receipt ordering,
  reconnect cursors, retention/expiry races, quotas and noisy-neighbor backlog load.
- **P03:** multi-node broker/database failover, host power loss and recovery objectives.
  Process restart on intact volumes is not a power-loss or replicated durability test.
- **N01/N02:** [native agent hook/sandbox checks](../../docs/security/agent-safety.md#pending-native-checks)
  remain pending. Docker service tests do not validate agent filesystem restrictions
  or trust/activate native hooks.

`DEVICE_ACKED` still means durable sealed storage on an authorized recipient device,
not decryption or reading. The fixture never produces that state. Proposed ADRs and
F0.4 A01–A07 / crypto E01–E06 review gates stay open. Dependabot #10 remains deferred;
this harness does not change its incompatible crypto pins.

## Recorded local validation

On 12 November 2026, `make harness-test` executed all 37 service cases (11 delivery
fixture cases, 10 F1.2 identity cases and 16 F1.3 API cases) with zero skips on Linux x86_64, .NET SDK
10.0.115, Docker Engine 29.9.3 and Compose 5.7.0. Cleanup verified removal of the
run's containers, volumes and network. The separate `make verify` passed 71
Gateway/authentication checks, 13 repository checks, 12 crypto checks and 13
contract checks, plus formatting and documentation checks. This is local subset
evidence; CI must rerun the checks for each submitted head and P01–P03 remain open.

## Lifecycle, credentials and failures

Each invocation generates a unique `amdn-f05-<run-id>` Compose project, isolated
named volumes, random loopback-only published ports and disposable credentials.
No arbitrary database URL, existing deployment or external broker is accepted.
Bootstrap SQL runs inside only the newly created PostgreSQL container; tests get
the restricted fixture login plus separate migration, provisioning and runtime
identity logins. They never receive the PostgreSQL administrator password. No production data, host directories other than
run configuration, Docker socket mounts or privileged containers are used.

Private configuration is mode 0600 inside an ignored mode 0700 directory under
.local/harness, except the NATS config (0444 inside that same private directory so
the capability-free container can read its bind mount). Generated credentials are not command arguments or committed files.
The runner redacts them from evidence, then removes private configuration. Progress
goes to stderr; a compact TOON result or actionable error goes to stdout. Exit codes
are 0 success, 1 runtime/prerequisite/cleanup failure, 2 invalid arguments.
`python3 tests/Harness/run.py --help` performs no service operations.

Sanitized stage logs and the xUnit TRX report are retained under the ignored
.local/harness-evidence/<run-id> path printed by the runner. They are not uploaded
as CI artifacts. Inspect the test-stage log and harness.trx for failed assertions.
A successful result requires every discovered test to execute and pass, and cleanup
to verify that no owned containers, volumes or networks remain.

Normal failures, timeouts, SIGINT and SIGTERM trigger cleanup. SIGKILL of the runner
or host loss cannot run a finally handler. If cleanup fails, the error names the
exact project; inspect containers and volumes with
`docker --context default ps -a --filter label=com.docker.compose.project=<project>`
and `docker --context default volume ls --filter label=com.docker.compose.project=<project>`;
also inspect networks with
`docker --context default network ls --filter label=com.docker.compose.project=<project>`.
Verify each resource's `amdn.harness.run` label matches the run ID before manually
removing it and its private directory. Never use a global prune or reset another
project to repair a harness run. Run again only after prerequisites are restored.
