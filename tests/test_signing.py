"""Tests for Ed25519 signing and verification."""
import os
import tempfile
import unittest
from pathlib import Path
from zt.signing import keygen, sign, verify


class SigningTests(unittest.TestCase):
    def test_keygen_and_sign_verify_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            priv = Path(tmp_dir) / "id_ed25519"
            pub = Path(tmp_dir) / "id_ed25519.pub"

            keygen(priv, pub)
            self.assertTrue(priv.is_file())
            self.assertTrue(pub.is_file())

            # Check permissions
            priv_mode = priv.stat().st_mode & 0o777
            pub_mode = pub.stat().st_mode & 0o777
            self.assertEqual(priv_mode, 0o600)
            self.assertEqual(pub_mode, 0o644)

            # Test signing string and bytes
            signature = sign("zero-trust-payload", priv)
            self.assertTrue(verify("zero-trust-payload", signature, pub))
            self.assertFalse(verify("tampered-payload", signature, pub))
            self.assertFalse(verify("zero-trust-payload", b"invalid_signature", pub))

    def test_signing_rejects_symlink_key(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            priv = Path(tmp_dir) / "key"
            pub = Path(tmp_dir) / "key.pub"
            keygen(priv, pub)

            symlink_key = Path(tmp_dir) / "sym_key"
            os.symlink(priv, symlink_key)

            with self.assertRaises(ValueError):
                sign("data", symlink_key)
