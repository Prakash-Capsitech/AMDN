"""Safety boundaries of the destructive fixture runner, without Docker access."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

RUNNER = Path(__file__).resolve().parents[1] / "Harness/run.py"
spec = importlib.util.spec_from_file_location("harness_runner", RUNNER)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class HarnessRunnerTests(unittest.TestCase):
    def failure_report(self, run, messages, outcome="Failed"):
        # TRX is the VSTest logger's serialized result contract. Definitions hold
        # method identities; display names, messages and output may hold secrets.
        root = ET.Element("TestRun", xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010")
        definitions = ET.SubElement(root, "TestDefinitions")
        results = ET.SubElement(root, "Results")
        for index, message in enumerate(messages):
            test = ET.SubElement(definitions, "UnitTest", id=str(index))
            ET.SubElement(test, "TestMethod", className="AMDN.Harness.Tests.EnrollmentAuthorityTests",
                          name="RequiresCurrentAuthority")
            result = ET.SubElement(results, "UnitTestResult", testId=str(index), outcome=outcome,
                                   testName="RequiresCurrentAuthority(token: display-secret)")
            output = ET.SubElement(result, "Output")
            ET.SubElement(output, "StdOut").text = "Bearer stdout-secret"
            error = ET.SubElement(output, "ErrorInfo")
            ET.SubElement(error, "Message").text = message
            ET.SubElement(error, "StackTrace").text = (
                "   at AMDN.Harness.Tests.EnrollmentAuthorityTests.RequiresCurrentAuthority() "
                "in /private-path/tests/Harness/EnrollmentAuthorityTests.cs:line 42\n"
                "Bearer stack-secret")
        summary = ET.SubElement(root, "ResultSummary")
        ET.SubElement(summary, "Counters", total=str(len(messages)), executed=str(len(messages)),
                      passed=str(len(messages)) if outcome == "Passed" else "0")
        ET.ElementTree(root).write(run.evidence / "harness.trx", encoding="utf-8")

    def run_result(self, messages, *, mode="exit", outcome="Failed", report=None):
        with tempfile.TemporaryDirectory() as temporary, patch.object(runner, "ROOT", Path(temporary)):
            run = runner.Run()
            (run.evidence / "service-logs.log").write_text("Bearer service-secret")

            def command(args, stage, **kwargs):
                if stage == "test":
                    self.failure_report(run, messages, outcome)
                    if report is not None:
                        (run.evidence / "harness.trx").write_text(report)
                    if mode == "missing":
                        (run.evidence / "harness.trx").unlink()
                    if mode == "exit":
                        raise runner.Failure("test failed; inspect the sanitized evidence directory")
                    if mode == "timeout":
                        raise subprocess.TimeoutExpired(args, 360)
                return ""

            output = io.StringIO()
            with patch.object(runner, "Run", return_value=run), \
                    patch.object(run, "setup"), patch.object(run, "command", side_effect=command), \
                    patch.object(runner.shutil, "which", return_value="available"), \
                    patch.object(runner.sys, "platform", "linux"), \
                    patch.object(runner.sys, "argv", [str(RUNNER)]), contextlib.redirect_stdout(output):
                status = runner.main()
            # Diagnostics must never turn a failure into success.
            self.assertEqual(0 if outcome == "Passed" else 1, status)
            self.assertFalse(run.private.exists())
            fields = dict((key, json.loads(value)) for key, value in
                          (line.split(": ", 1) for line in output.getvalue().splitlines()))
            self.assertEqual("complete", fields["cleanup"])
            return fields

    def test_failure_projection_reports_assertion_without_test_data(self):
        # Oracle: a worked xUnit equality failure in a TRX result. Dumping raw
        # evidence leaks the canaries; omitting diagnostics hides the assertion.
        fields = self.run_result([
            "Assert.Equal() Failure: Values differ\nExpected: 200\nActual:   403\n"
            "Password=connection-secret; Bearer token-secret\n"
            "-----BEGIN PRIVATE KEY-----\nkey-secret\n-----END PRIVATE KEY-----",
            'Assert.Equal() Failure: Strings differ\nExpected: "expected-secret"\nActual: "actual-secret"',
        ])
        self.assertEqual(2, fields["test_failures"])
        self.assertEqual(
            "AMDN.Harness.Tests.EnrollmentAuthorityTests.RequiresCurrentAuthority; outcome=Failed; "
            "kind=Assert.Equal; expected=200; actual=403; at=EnrollmentAuthorityTests.cs:42",
            fields["test_failure_1"])
        self.assertNotIn("expected=", fields["test_failure_2"])
        self.assertNotIn("actual=", fields["test_failure_2"])
        self.assertNotIn("secret", json.dumps(fields))
        self.assertNotIn("PRIVATE KEY", json.dumps(fields))
        self.assertNotIn("private-path", json.dumps(fields))

    def test_projection_covers_timeout_and_failed_counters_with_bounded_output(self):
        for mode in ("timeout", "counters"):
            with self.subTest(mode=mode):
                fields = self.run_result(["Assert.True() Failure\nExpected: True\nActual: False"] * 12,
                                          mode=mode, outcome="NotExecuted")
                self.assertEqual(12, fields["test_failures"])
                self.assertEqual(2, fields["test_failures_omitted"])
                self.assertNotIn("test_failure_11", fields)
                self.assertIn("expected=True; actual=False", fields["test_failure_1"])

    def test_unusable_report_does_not_hide_original_failure_or_cleanup(self):
        for report in ("<broken>Bearer parser-secret", "x" * (2 * 1024 * 1024 + 1)):
            with self.subTest(size=len(report)):
                fields = self.run_result([], report=report)
                self.assertEqual("unavailable", fields["test_diagnostics"])
                self.assertTrue(fields["error"].startswith("test failed"))
                self.assertNotIn("parser-secret", json.dumps(fields))

    def test_missing_report_and_successful_run(self):
        fields = self.run_result([], mode="missing")
        self.assertEqual("unavailable", fields["test_diagnostics"])
        fields = self.run_result([""], mode="success", outcome="Passed")
        self.assertEqual("passed", fields["result"])
        self.assertEqual(1, fields["tests"])
        self.assertFalse(any(key.startswith("test_failure") or key == "test_diagnostics" for key in fields))

    def test_exception_and_unknown_message_projection(self):
        fields = self.run_result([
            "Npgsql.PostgresException : 42501: permission denied; Password=exception-secret",
            "Bearer unknown-secret\nExpected: 1234\nActual: 5678",
            "Assert.Equal() Failure: Values differ\nExpected: Unauthorized\nActual: Forbidden",
        ])
        self.assertIn("kind=Npgsql.PostgresException", fields["test_failure_1"])
        self.assertNotIn("expected=", fields["test_failure_2"])
        self.assertIn("expected=Unauthorized; actual=Forbidden", fields["test_failure_3"])
        self.assertNotIn("secret", json.dumps(fields))

    def test_help_and_invalid_arguments_need_no_dependencies(self):
        for arguments, expected in ((["--help"], 0), (["--database", "production"], 2)):
            result = subprocess.run([sys.executable, str(RUNNER), *arguments],
                                    env={"PATH": ""}, capture_output=True, text=True)
            self.assertEqual(expected, result.returncode)
            self.assertNotIn("harness: start", result.stderr)
            self.assertIn("--help", result.stdout)

    def test_cleanup_refuses_foreign_labels_but_erases_credentials(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(runner, "ROOT", Path(temporary)):
            run = runner.Run()
            (run.private / "state.json").write_text(run.secrets[1])
            report = run.evidence / "harness.trx"
            report.write_text(run.secrets[1])
            run.started = True
            calls = []

            def fake_command(args, stage, **_):
                calls.append(args)
                return "foreign-container" if stage == "owned-container" else "another-run"

            with patch.object(run, "command", side_effect=fake_command):
                with self.assertRaisesRegex(runner.Failure, "ownership mismatch"):
                    run.cleanup()
            self.assertFalse(any("down" in args for args in calls))
            self.assertFalse(run.private.exists())
            self.assertEqual("[REDACTED]", report.read_text())

    def test_failed_teardown_cannot_leave_credentials_in_evidence(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(runner, "ROOT", Path(temporary)):
            run = runner.Run()
            report = run.evidence / "failure.log"
            report.write_text("connection failed " + run.secrets[2])
            run.started = True

            def fake_command(args, stage, **_):
                if stage == "cleanup":
                    raise runner.Failure("engine unavailable")
                return ""

            with patch.object(run, "command", side_effect=fake_command):
                with self.assertRaisesRegex(runner.Failure, "engine unavailable"):
                    run.cleanup()
            self.assertFalse(run.private.exists())
            self.assertNotIn(run.secrets[2], report.read_text())


if __name__ == "__main__":
    unittest.main()
