"""Tests for SafeStack Zero Trust CLI commands."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from zt.cli import main


class CliTests(unittest.TestCase):
    def test_cli_keygen(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            priv = Path(tmp_dir) / "priv.pem"
            pub = Path(tmp_dir) / "pub.pem"
            code = main(["keygen", str(priv), str(pub)])
            self.assertEqual(code, 0)
            self.assertTrue(priv.is_file())
            self.assertTrue(pub.is_file())

    def test_cli_device_and_policy_workflow(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = str(Path(tmp_dir) / "test.db")

            # Add device
            self.assertEqual(
                main(["device-add", "--db", db_path, "--id", "dev-1", "--name", "laptop", "--owner", "alice", "--posture", "compliant"]),
                0,
            )

            # Add allow policy
            self.assertEqual(
                main(["policy-add", "--db", db_path, "--effect", "allow", "--subject", "alice", "--resource", "db", "--action", "read", "--min-posture", "compliant"]),
                0,
            )

            # Authorize: should succeed (exit code 0)
            f = io.StringIO()
            with redirect_stdout(f):
                code = main(["authorize", "--db", db_path, "--device", "dev-1", "--subject", "alice", "--resource", "db", "--action", "read"])
            self.assertEqual(code, 0)
            out = json.loads(f.getvalue())
            self.assertTrue(out["allowed"])

            # Authorize unauthorized action: should return exit code 2
            f_fail = io.StringIO()
            with redirect_stdout(f_fail):
                code_fail = main(["authorize", "--db", db_path, "--device", "dev-1", "--subject", "alice", "--resource", "db", "--action", "write"])
            self.assertEqual(code_fail, 2)

    def test_cli_user_add_and_auth(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = str(Path(tmp_dir) / "test.db")

            self.assertEqual(
                main(["user-add", "--db", db_path, "--username", "alice", "--password", "secure_password_123"]),
                0,
            )

            self.assertEqual(
                main(["user-auth", "--db", db_path, "--username", "alice", "--password", "secure_password_123"]),
                0,
            )

            self.assertEqual(
                main(["user-auth", "--db", db_path, "--username", "alice", "--password", "wrong_password"]),
                1,
            )

    def test_cli_sbom(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            src = Path(tmp_dir) / "src"
            src.mkdir()
            (src / "test.py").write_text("x = 1")
            out = Path(tmp_dir) / "sbom.json"

            self.assertEqual(main(["sbom", str(src), str(out)]), 0)
            self.assertTrue(out.is_file())
