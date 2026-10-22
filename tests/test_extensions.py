"""Tests for SafeStack platform extensions."""
import os
import tempfile
import unittest
from pathlib import Path
from zt.extensions import (
    append_immutable,
    certificate_expiry,
    compliance_check,
    container_digest,
    evidence_seal,
    mesh_peer,
    phishing_simulation,
    privacy_profile,
    signed_update_manifest,
    verify_immutable,
)


class ExtensionTests(unittest.TestCase):
    def test_hash_chain(self):
        with tempfile.NamedTemporaryFile() as f:
            previous = append_immutable(f.name, {"kind": "login"})
            append_immutable(f.name, {"kind": "allow"}, previous)
            self.assertTrue(verify_immutable(f.name))
            Path(f.name).write_text(Path(f.name).read_text().replace("login", "tampered"))
            self.assertFalse(verify_immutable(f.name))

    def test_immutable_corrupted_lines_handled_safely(self):
        with tempfile.NamedTemporaryFile() as f:
            append_immutable(f.name, {"kind": "event1"})
            # Corrupt the file with random text
            with open(f.name, "a") as stream:
                stream.write("not valid json at all\n")
            self.assertFalse(verify_immutable(f.name))

    def test_safe_boundaries(self):
        self.assertEqual(compliance_check([{"id": "C1", "title": "MFA"}], set())[0]["status"], "review")
        self.assertEqual(mesh_peer("pi", "pub", "10.8.0.2/32")["name"], "pi")
        self.assertFalse(phishing_simulation("training", "a@example.com")["sent"])
        self.assertEqual(len(evidence_seal(b"x")["sha256"]), 64)
        self.assertEqual(len(evidence_seal("string_evidence")["sha256"]), 64)

    def test_mesh_peer_ip_validation(self):
        with self.assertRaises(ValueError):
            mesh_peer("bad_peer", "pub_key", "invalid_ip_format")

    def test_container_digest(self):
        digest = container_digest("alpine:latest")
        self.assertEqual(len(digest), 64)
        with self.assertRaises(ValueError):
            container_digest("")

    def test_privacy_profile(self):
        settings = {"telemetry": False, "location": False, "microphone": True}
        profile = {"telemetry": False, "location": False}
        res = privacy_profile(settings, profile)
        self.assertTrue(res["telemetry"])
        self.assertTrue(res["location"])

    def test_signed_update_manifest(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            f1 = Path(tmp_dir) / "f1.bin"
            f1.write_bytes(b"content1")
            manifest = signed_update_manifest([f1])
            self.assertEqual(manifest["schema"], "safestack/update-v1")
            self.assertEqual(len(manifest["files"]), 1)
            self.assertEqual(manifest["files"][0]["sha256"], evidence_seal(b"content1")["sha256"])
