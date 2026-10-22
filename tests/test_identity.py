"""Tests for Identity and Access Management."""
import tempfile
import unittest
from zt.identity import (
    assign_role,
    authenticate,
    create_user,
    disable_user,
    get_roles,
    hash_password,
    validate_username,
    verify_password,
)
from zt.store import Store


class IdentityTests(unittest.TestCase):
    def test_password_hash_and_auth(self):
        hashed = hash_password("a secure password")
        self.assertTrue(verify_password("a secure password", hashed))
        self.assertFalse(verify_password("wrong password", hashed))

        with tempfile.NamedTemporaryFile() as f:
            db = Store(f.name)
            create_user(db, "alice", "a secure password")
            assign_role(db, "alice", "operator")
            self.assertTrue(authenticate(db, "alice", "a secure password"))
            self.assertFalse(authenticate(db, "alice", "wrong password"))

    def test_short_password_rejected(self):
        with self.assertRaises(ValueError):
            hash_password("short")

    def test_invalid_username_rejected(self):
        with self.assertRaises(ValueError):
            validate_username("bad username with space")
        with self.assertRaises(ValueError):
            validate_username("a")  # too short
        with self.assertRaises(ValueError):
            validate_username("x" * 65)  # too long

    def test_verify_password_bounds_and_tampered_hashes(self):
        # Invalid format
        self.assertFalse(verify_password("password", "invalid_format"))
        # Invalid algorithm
        self.assertFalse(verify_password("password", "sha1$10000$c2FsdA==$ZGlnZXN0"))
        # Rounds too small (< 10_000)
        self.assertFalse(verify_password("password", "pbkdf2_sha256$500$c2FsdA==$ZGlnZXN0"))
        # Rounds excessively high (> 5_000_000) to prevent CPU DoS
        self.assertFalse(verify_password("password", "pbkdf2_sha256$99999999$c2FsdA==$ZGlnZXN0"))
        # Non-string input
        self.assertFalse(verify_password(12345, "pbkdf2_sha256$600000$c2FsdA==$ZGlnZXN0"))

    def test_user_disable_and_roles(self):
        with Store(":memory:") as db:
            create_user(db, "bob", "a very secure password 123")
            assign_role(db, "bob", "auditor")
            assign_role(db, "bob", "admin")
            self.assertEqual(get_roles(db, "bob"), ["admin", "auditor"])

            # Verify authenticates when active
            self.assertTrue(authenticate(db, "bob", "a very secure password 123"))

            # Disable user
            disable_user(db, "bob")
            self.assertFalse(authenticate(db, "bob", "a very secure password 123"))
