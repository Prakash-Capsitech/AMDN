#!/usr/bin/env python3
"""Own one disposable F0.5 run; never accept an external service endpoint."""
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "tests/Harness/AMDN.Harness.Tests.csproj"


def emit(**fields):
    # Flat TOON object; JSON string quoting is compatible with TOON escapes.
    for key, value in fields.items():
        print(f"{key}: {json.dumps(value, ensure_ascii=False)}", flush=True)


class Failure(Exception):
    pass


class Run:
    def __init__(self):
        self.run_id = uuid.uuid4().hex
        self.project = "amdn-f05-" + self.run_id
        local = ROOT / ".local/harness"
        local.mkdir(parents=True, exist_ok=True)
        self.private = Path(tempfile.mkdtemp(prefix=self.run_id + "-", dir=local))
        self.evidence = ROOT / ".local/harness-evidence" / self.run_id
        self.evidence.mkdir(parents=True, mode=0o700)
        self.secrets = [secrets.token_hex(32) for _ in range(7)]
        self.env = dict(os.environ, HARNESS_RUN_ID=self.run_id,
                        HARNESS_PRIVATE_DIR=str(self.private),
                        AMDN_HARNESS_STATE=str(self.private / "state.json"),
                        DOTNET_NOLOGO="1", DOTNET_CLI_TELEMETRY_OPTOUT="1")
        # Explicit local context; no ambient remote daemon or Compose overrides.
        for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "COMPOSE_FILE", "COMPOSE_PROFILES"):
            self.env.pop(key, None)
        self.docker = ["docker", "--context", "default"]
        self.compose = self.docker + ["compose", "--project-name", self.project,
                                     "--file", str(ROOT / "tests/Harness/compose.yaml")]
        self.started = False
        self.counter = 0

    def redact(self, value):
        for secret in self.secrets:
            value = value.replace(secret, "[REDACTED]")
        return value

    def failure_diagnostics(self):
        # TRX messages/display names can contain arbitrary data. Publish only
        # method metadata and a small vocabulary of diagnostic facts, never a
        # truncated raw message, captured output, or service log.
        try:
            with (self.evidence / "harness.trx").open("rb") as report:
                data = report.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024 or b"<!DOCTYPE" in data or b"<!ENTITY" in data:
                return dict(test_diagnostics="unavailable")
            tree = ET.fromstring(data)
        except (OSError, ET.ParseError):
            return dict(test_diagnostics="unavailable")
        methods = {}
        for test in tree.findall("./{*}TestDefinitions/{*}UnitTest"):
            method = test.find("{*}TestMethod")
            if method is not None:
                name = method.get("className", "") + "." + method.get("name", "")
                if re.fullmatch(r"AMDN\.Harness\.Tests\.[A-Za-z_][A-Za-z_0-9]{0,99}\."
                                r"[A-Za-z_][A-Za-z_0-9]{0,199}", name):
                    methods[test.get("id")] = self.redact(name)
        failures = [result for result in tree.findall("./{*}Results/{*}UnitTestResult")
                    if result.get("outcome") != "Passed"]
        fields = dict(test_failures=len(failures), test_failures_omitted=max(0, len(failures) - 10))
        for index, result in enumerate(failures[:10], 1):
            outcome = result.get("outcome")
            if outcome not in ("Failed", "NotExecuted", "Error", "Timeout", "Aborted", "Inconclusive"):
                outcome = "other"
            details = [methods.get(result.get("testId"), "unknown test"), "outcome=" + outcome]
            message = self.redact(result.findtext("./{*}Output/{*}ErrorInfo/{*}Message", ""))
            assertion = re.match(r"Assert\.(Equal|NotEqual|True|False|Null|NotNull|Empty|NotEmpty|"
                                 r"Single|Contains|DoesNotContain|Throws|ThrowsAny|IsType|IsAssignableFrom|"
                                 r"InRange|All|Collection|Fail)\(\) Failure\b", message)
            if assertion:
                details.append("kind=Assert." + assertion[1])
                for label in ("Expected", "Actual"):
                    scalar = re.search(r"^" + label + r": +(-?[0-9]{1,4}|True|False|null|"
                                       r"OK|Created|NoContent|BadRequest|Unauthorized|Forbidden|NotFound|"
                                       r"Conflict|TooManyRequests|InternalServerError)\r?$", message, re.M)
                    if scalar:
                        details.append(label.lower() + "=" + scalar[1])
            else:
                for kind in ("Npgsql.PostgresException", "Npgsql.NpgsqlException", "System.TimeoutException",
                             "System.OperationCanceledException", "System.Threading.Tasks.TaskCanceledException",
                             "System.InvalidOperationException", "System.Net.Http.HttpRequestException"):
                    if message.startswith(kind + " :") or message.startswith(kind + ":"):
                        details.append("kind=" + kind)
                        break
            stack = self.redact(result.findtext("./{*}Output/{*}ErrorInfo/{*}StackTrace", ""))
            location = re.search(r"[/\\]tests[/\\]Harness[/\\]([A-Za-z_][A-Za-z_0-9]{0,99}\.cs)"
                                 r":line ([0-9]{1,6})\r?$", stack, re.M)
            if location:
                details.append("at=" + location[1] + ":" + location[2])
            fields[f"test_failure_{index}"] = "; ".join(details)
        return fields

    def command(self, args, stage, *, data=None, timeout=120):
        self.counter += 1
        print(f"harness: {stage}", file=sys.stderr, flush=True)
        process = subprocess.Popen(args, cwd=ROOT, env=self.env, text=True,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            output, _ = process.communicate(data, timeout=timeout)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            output, _ = process.communicate()
            (self.evidence / f"{self.counter:02}-{stage}.log").write_text(self.redact(output))
            raise
        (self.evidence / f"{self.counter:02}-{stage}.log").write_text(self.redact(output))
        if process.returncode:
            raise Failure(f"{stage} failed; inspect the sanitized evidence directory")
        return output.strip()

    def owned(self, kind):
        args = ["ps", "-aq"] if kind == "container" else [kind, "ls", "-q"]
        return self.command(self.docker + args + ["--filter", f"label=com.docker.compose.project={self.project}"],
                            "owned-" + kind).splitlines()

    def verify_ownership(self, kind, ids):
        for identifier in ids:
            label = self.command(self.docker + [kind, "inspect", "--format",
                                 '{{index .Labels "amdn.harness.run"}}' if kind != "container" else
                                 '{{index .Config.Labels "amdn.harness.run"}}', identifier], "ownership")
            if label != self.run_id:
                raise Failure("resource ownership mismatch; refusing destructive cleanup")

    def setup(self):
        endpoint = self.command(self.docker + ["context", "inspect", "default", "--format",
                                '{{.Endpoints.docker.Host}}'], "local-context")
        if not endpoint.startswith("unix://"):
            raise Failure("default Docker context must use a local Unix socket")
        self.command(self.docker + ["info", "--format", '{{.ServerVersion}}'], "engine")
        (self.private / "postgres_password").write_text(self.secrets[0])
        (self.private / "nats.conf").write_text(
            'port: 4222\nauthorization { token: "' + self.secrets[2] + '" }\n'
            'jetstream { store_dir: "/data", max_memory_store: 64MB, max_file_store: 128MB }\n')
        for file in self.private.iterdir():
            file.chmod(0o600)
        # NATS drops all capabilities, including DAC override. Only the mounted
        # file is world-readable; its private parent remains mode 0700 on the host.
        (self.private / "nats.conf").chmod(0o444)
        self.started = True  # Partial startup also needs cleanup.
        self.command(self.compose + ["up", "--detach", "--wait", "--wait-timeout", "90"], "start", timeout=300)
        ids = {}
        ports = {}
        for service, port in (("postgres", "5432"), ("nats", "4222")):
            ids[service] = self.command(self.compose + ["ps", "-q", service], "identify-" + service)
            self.verify_ownership("container", [ids[service]])
            address = self.command(self.compose + ["port", service, port], "port-" + service)
            host, number = address.rsplit(":", 1)
            if host != "127.0.0.1" or not 0 < int(number) < 65536:
                raise Failure("service must bind a loopback-only ephemeral port")
            ports[service] = int(number)
        sql = (ROOT / "tests/Harness/fixture.sql").read_text().replace(
            "__APP_PASSWORD__", self.secrets[1]).replace("__RUN_ID__", self.run_id)
        self.command(self.docker + ["exec", "-i", ids["postgres"], "psql", "-X", "-v",
                     "ON_ERROR_STOP=1", "-U", "postgres", "-d", "amdn_harness"], "bootstrap", data=sql)
        roles = (ROOT / "src/Infrastructure/Identity/Migrations/roles.sql").read_text()
        for suffix, group, secret in (("runtime", "runtime", self.secrets[3]),
                                      ("provisioner", "provisioner", self.secrets[4]),
                                      ("migrator", "owner", self.secrets[5]),
                                      ("enrollment", "enrollment", self.secrets[6])):
            # All values are fixed role names or generated hex, never caller input.
            roles += (f"CREATE ROLE harness_identity_{suffix} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS "
                      f"NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '{secret}';\n")
            inherit = "FALSE" if suffix == "migrator" else "TRUE"
            assume = "TRUE" if suffix == "migrator" else "FALSE"
            roles += (f"GRANT amdn_identity_{group} TO harness_identity_{suffix} "
                      f"WITH INHERIT {inherit}, SET {assume};\n")
            roles += f"GRANT CONNECT ON DATABASE amdn_harness TO harness_identity_{suffix};\n"
        roles += "GRANT CREATE ON DATABASE amdn_harness TO amdn_identity_owner;\n"
        self.command(self.docker + ["exec", "-i", ids["postgres"], "psql", "-X", "-v",
                     "ON_ERROR_STOP=1", "-U", "postgres", "-d", "amdn_harness"], "identity-roles", data=roles)
        state = dict(RunId=self.run_id, PostgresPort=ports["postgres"], NatsPort=ports["nats"],
                     AppPassword=self.secrets[1], NatsToken=self.secrets[2],
                     IdentityRuntimePassword=self.secrets[3], IdentityProvisionerPassword=self.secrets[4],
                     IdentityMigrationPassword=self.secrets[5],
                     IdentityEnrollmentPassword=self.secrets[6],
                     PostgresContainer=ids["postgres"], NatsContainer=ids["nats"])
        (self.private / "state.json").write_text(json.dumps(state))
        (self.private / "state.json").chmod(0o600)

    def test(self):
        self.command(["dotnet", "restore", str(PROJECT), "--locked-mode"], "restore", timeout=180)
        self.command(["dotnet", "build", str(PROJECT), "--no-restore", "-c", "Release"], "build")
        self.command(["dotnet", str(ROOT / "tests/Harness/bin/Release/net10.0/AMDN.Harness.Tests.dll"),
                      "identity-migrate"], "identity-migrate")
        self.command(["dotnet", "format", str(PROJECT), "--verify-no-changes", "--no-restore"], "format")
        self.command(["dotnet", "test", str(PROJECT), "--no-restore", "--no-build", "-c", "Release",
                      "--logger", "trx;LogFileName=harness.trx", "--results-directory", str(self.evidence),
                      "--blame-hang-timeout", "90s", "--blame-hang-dump-type", "none"], "test", timeout=360)
        tree = ET.parse(self.evidence / "harness.trx")
        counts = tree.find(".//{*}Counters").attrib
        total = int(counts["total"])
        if total == 0 or int(counts["passed"]) != total or int(counts["executed"]) != total:
            raise Failure("not every discovered harness test executed and passed")
        return total

    def cleanup(self):
        try:
            if self.started:
                for kind in ("container", "volume", "network"):
                    self.verify_ownership(kind, self.owned(kind))
                try:
                    self.command(self.compose + ["logs", "--no-color", "--tail", "150"], "service-logs")
                except Failure:
                    pass  # Diagnostic failure must not prevent resource cleanup.
                self.command(self.compose + ["down", "--volumes", "--timeout", "10"], "cleanup")
                if any(self.owned(kind) for kind in ("container", "volume", "network")):
                    raise Failure("owned resources remain after cleanup")
        finally:
            # Do not retain credentials even if engine access/cleanup fails.
            try:
                for path in self.evidence.rglob("*"):
                    if path.is_file():
                        path.write_text(self.redact(path.read_text(errors="replace")))
            finally:
                shutil.rmtree(self.private)


def main():
    if sys.argv[1:] == ["--help"]:
        emit(description="Run disposable PostgreSQL/JetStream F0.5 fixtures and clean up",
             usage="python3 tests/Harness/run.py [--help]",
             requires="Linux, local Docker Engine + Compose v2, .NET SDK from global.json",
             examples="make harness-test; python3 tests/Harness/run.py",
             scope="synthetic fixtures; native N01/N02 and production integration remain pending")
        return 0
    if sys.argv[1:]:
        emit(error="unknown argument(s): " + " ".join(sys.argv[1:]),
             help="Valid flags: --help. Run: python3 tests/Harness/run.py")
        return 2
    run = None
    failure = None
    cleaned = False
    total = 0
    try:
        if sys.platform != "linux" or not shutil.which("docker") or not shutil.which("dotnet"):
            raise Failure("requires Linux, local Docker Engine/Compose and the pinned .NET SDK")
        run = Run()
        run.setup()
        total = run.test()
    except (Exception, KeyboardInterrupt) as exc:
        failure = str(exc) if isinstance(exc, Failure) else "run interrupted or dependency unavailable"
    finally:
        if run:
            try:
                run.cleanup()
                cleaned = True
            except (Exception, KeyboardInterrupt):
                failure = "cleanup failed; inspect evidence and remove only this run's labeled resources"
    if failure:
        emit(error=failure, cleanup="complete" if cleaned else "incomplete",
             project=run.project if run else "none", evidence=str(run.evidence) if run else "none",
             help="Inspect evidence, check prerequisites in tests/Harness/README.md, then run make harness-test")
        if run:
            emit(**run.failure_diagnostics())
        return 1
    emit(result="passed", tests=total, cleanup="complete", evidence=str(run.evidence),
         pending="production integration P01-P03; native N01/N02")
    return 0


def interrupted(*_):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
