"""Tests for Zero Trust SQLite store."""
import os
import tempfile
import unittest
from pathlib import Path
from zt.store import Store


class StoreTests(unittest.TestCase):
    def test_store_creates_file_with_0600_mode(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test.db"
            with Store(str(db_path)) as store:
                store.add_device(("d1", "node-1", "alice", "compliant", "2026-10-22"))
                dev = store.device("d1")
                self.assertIsNotNone(dev)
                self.assertEqual(dev["name"], "node-1")

            mode = db_path.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_store_rejects_symlink_path(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            real_db = Path(tmp_dir) / "real.db"
            link_db = Path(tmp_dir) / "link.db"
            real_db.touch()
            os.symlink(real_db, link_db)

            with self.assertRaises(ValueError):
                Store(str(link_db))

    def test_store_memory_mode(self):
        with Store(":memory:") as store:
            store.add_device(("m1", "mem-node", "bob", "compliant", "now"))
            self.assertEqual(store.device("m1")["name"], "mem-node")

    def test_store_policy_precedence_ordering(self):
        with Store(":memory:") as store:
            store.add_policy(("p1", "allow", "alice", "vpn", "connect", "compliant"))
            store.add_policy(("p2", "deny", "alice", "vpn", "connect", "compliant"))
            policies = store.policies("alice", "vpn", "connect")
            self.assertEqual(len(policies), 2)
            # Deny must be first because ORDER BY effect DESC
            self.assertEqual(policies[0]["effect"], "deny")
            self.assertEqual(policies[1]["effect"], "allow")
