"""Tests for Security Operations Center event processing and detection."""
import os
import tempfile
import unittest
from pathlib import Path
from zt.soc import append_event, detect, read_events, validate_event


class SocTests(unittest.TestCase):
    def test_brute_force_rule(self):
        events = [
            {"kind": "authentication", "subject": "alice", "success": False, "source": "vpn", "timestamp": "now"}
            for _ in range(5)
        ]
        alerts = detect(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "brute_force_suspected")
        self.assertEqual(alerts[0]["subject"], "alice")
        self.assertEqual(alerts[0]["severity"], "high")

    def test_unauthorized_and_posture_alerts(self):
        events = [
            {"kind": "authorization", "subject": "bob", "source": "laptop", "reason": "device_not_registered", "timestamp": "now", "success": False},
            {"kind": "authorization", "subject": "charlie", "source": "phone", "reason": "device_posture_below_policy", "timestamp": "now", "success": False},
        ]
        alerts = detect(events)
        types = [a["type"] for a in alerts]
        self.assertIn("unauthorized_access_attempt", types)
        self.assertIn("posture_violation", types)

    def test_schema_validation(self):
        self.assertTrue(validate_event({"kind": "x"}))
        self.assertFalse(
            validate_event({
                "kind": "auth",
                "source": "vpn",
                "subject": "alice",
                "success": True,
                "timestamp": "2026-10-22T00:00:00Z",
            })
        )

    def test_append_and_read_events(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "events.jsonl"
            ev = {
                "kind": "auth",
                "source": "lan",
                "subject": "user1",
                "success": True,
                "timestamp": "now",
            }
            append_event(log_path, ev)
            rows = read_events(log_path)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["subject"], "user1")

            # Check permissions
            self.assertEqual(log_path.stat().st_mode & 0o777, 0o600)

    def test_append_event_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            real_file = Path(tmp_dir) / "real.log"
            real_file.touch()
            link = Path(tmp_dir) / "link.log"
            os.symlink(real_file, link)

            ev = {"kind": "auth", "source": "lan", "subject": "user1", "success": True, "timestamp": "now"}
            with self.assertRaises(ValueError):
                append_event(link, ev)
