import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class HookTests(unittest.TestCase):
    def test_push_policy(self):
        hook = ROOT / ".githooks/pre-push"
        for remote, branch, allowed in [
            ("origin", "feature", False), ("no-mistakes", "main", False),
            ("no-mistakes", "master", False), ("no-mistakes", "feature", True),
        ]:
            with self.subTest(remote=remote, branch=branch):
                result = subprocess.run(
                    ["bash", str(hook), remote], input=f"refs/heads/{branch} {'1'*40} refs/heads/{branch} {'0'*40}\n",
                    text=True, capture_output=True,
                )
                self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_staged_secret_filename_is_rejected_but_template_is_allowed(self):
        with tempfile.TemporaryDirectory() as folder:
            env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
            def git(*args):
                subprocess.run(["git", *args], cwd=folder, env=env, check=True, capture_output=True)
            git("init", "-q")
            for name, allowed in [(".env.example", True), (".env", False)]:
                (Path(folder) / name).write_text("EXAMPLE=placeholder\n")
                git("add", name)
                result = subprocess.run(["bash", str(ROOT / ".githooks/pre-commit")],
                                        cwd=folder, env=env, capture_output=True)
                self.assertEqual(result.returncode == 0, allowed)
