"""Tests for Policy as Code parser and validator."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from zt.policy import load, validate_policy


class PolicyTests(unittest.TestCase):
    def test_valid_document(self):
        with tempfile.NamedTemporaryFile(mode="w+") as f:
            json.dump(
                {
                    "policies": [
                        {
                            "id": "p",
                            "effect": "deny",
                            "subject": "*",
                            "resource": "*",
                            "action": "*",
                            "min_posture": "unknown",
                        }
                    ]
                },
                f,
            )
            f.flush()
            self.assertEqual(len(load(f.name)), 1)

    def test_invalid_document(self):
        with tempfile.NamedTemporaryFile(mode="w+") as f:
            json.dump({"policies": [{"id": "p", "effect": "permit"}]}, f)
            f.flush()
            with self.assertRaises(ValueError):
                load(f.name)

    def test_validate_policy_individual_errors(self):
        self.assertEqual(validate_policy("not a dict"), ["policy must be an object"])

        # Missing fields
        errors = validate_policy({"id": "p1"})
        self.assertTrue(any("missing:" in e for e in errors))

        # Invalid effect and posture
        errors = validate_policy({
            "id": "p1",
            "effect": "allow_all",
            "subject": "alice",
            "resource": "vpn",
            "action": "connect",
            "min_posture": "super_compliant",
        })
        self.assertTrue(any("effect must be allow or deny" in e for e in errors))
        self.assertTrue(any("min_posture is invalid" in e for e in errors))

    def test_policy_load_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            real_file = Path(tmp_dir) / "policy.json"
            real_file.write_text(json.dumps([{"id": "p", "effect": "deny", "subject": "*", "resource": "*", "action": "*", "min_posture": "unknown"}]))
            link = Path(tmp_dir) / "link.json"
            os.symlink(real_file, link)

            with self.assertRaises(ValueError):
                load(link)
