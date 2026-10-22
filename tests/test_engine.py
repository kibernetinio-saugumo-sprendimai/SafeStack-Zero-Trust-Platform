"""Tests for Zero Trust policy evaluation engine."""
import unittest
from zt.engine import evaluate
from zt.store import Store


class EngineTests(unittest.TestCase):
    def test_default_deny_and_allow(self):
        with Store(":memory:") as db:
            db.add_device(("d1", "laptop", "alice", "compliant", "now"))
            # Default deny when no policies match
            self.assertFalse(evaluate(db, "d1", "alice", "vpn", "connect").allowed)

            # Allow when matching policy is present
            db.add_policy(("p1", "allow", "alice", "vpn", "connect", "compliant"))
            decision = evaluate(db, "d1", "alice", "vpn", "connect")
            self.assertTrue(decision.allowed)
            self.assertEqual(decision.reason, "policy_allow")

    def test_posture_blocks(self):
        with Store(":memory:") as db:
            db.add_device(("d1", "laptop", "alice", "degraded", "now"))
            db.add_policy(("p1", "allow", "alice", "vpn", "connect", "compliant"))
            decision = evaluate(db, "d1", "alice", "vpn", "connect")
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, "device_posture_below_policy")

    def test_unregistered_device_blocked(self):
        with Store(":memory:") as db:
            decision = evaluate(db, "unknown-device", "alice", "vpn", "connect")
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, "device_not_registered")

    def test_explicit_deny_overrides_allow(self):
        with Store(":memory:") as db:
            db.add_device(("d1", "workstation", "bob", "compliant", "now"))
            # Add an allow policy and a deny policy
            db.add_policy(("p1", "allow", "bob", "database", "write", "compliant"))
            db.add_policy(("p2", "deny", "bob", "database", "write", "compliant"))
            decision = evaluate(db, "d1", "bob", "database", "write")
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, "explicit_deny")

    def test_wildcard_matching(self):
        with Store(":memory:") as db:
            db.add_device(("d1", "workstation", "charlie", "compliant", "now"))
            # Add wildcard policy for all resources
            db.add_policy(("p_wild", "allow", "charlie", "*", "*", "compliant"))
            decision = evaluate(db, "d1", "charlie", "any_service", "read")
            self.assertTrue(decision.allowed)
            self.assertEqual(decision.reason, "policy_allow")
