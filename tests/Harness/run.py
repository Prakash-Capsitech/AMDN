#!/usr/bin/env python3
"""Own one disposable F0.5 run; never accept an external service endpoint."""
import json
import os
from pathlib import Path
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
        self.secrets = [secrets.token_hex(32) for _ in range(3)]
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
        state = dict(RunId=self.run_id, PostgresPort=ports["postgres"], NatsPort=ports["nats"],
                     AppPassword=self.secrets[1], NatsToken=self.secrets[2],
                     PostgresContainer=ids["postgres"], NatsContainer=ids["nats"])
        (self.private / "state.json").write_text(json.dumps(state))
        (self.private / "state.json").chmod(0o600)

    def test(self):
        self.command(["dotnet", "restore", str(PROJECT), "--locked-mode"], "restore", timeout=180)
        self.command(["dotnet", "build", str(PROJECT), "--no-restore", "-c", "Release"], "build")
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
        return 1
    emit(result="passed", tests=total, cleanup="complete", evidence=str(run.evidence),
         pending="production role/pool integration; native N01/N02")
    return 0


def interrupted(*_):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
