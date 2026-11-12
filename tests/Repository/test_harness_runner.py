"""Safety boundaries of the destructive fixture runner, without Docker access."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

RUNNER = Path(__file__).resolve().parents[1] / "Harness/run.py"
spec = importlib.util.spec_from_file_location("harness_runner", RUNNER)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class HarnessRunnerTests(unittest.TestCase):
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
