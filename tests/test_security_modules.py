"""Tests for Encrypted Secrets Store and Supply Chain SBOM."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from zt.secrets import generate_key, get, names, put
from zt.supply_chain import digest, sbom, write_sbom


class SecurityModuleTests(unittest.TestCase):
    def test_secret_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "key"
            store = Path(d) / "secrets"
            generate_key(key)
            put(store, key, "api", "value")
            put(store, key, "second", "two")
            self.assertEqual(get(store, key, "api"), "value")
            self.assertEqual(names(store, key), ["api", "second"])

    def test_secret_missing_key_raises_key_error(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "key"
            store = Path(d) / "secrets"
            generate_key(key)
            put(store, key, "api", "value")
            with self.assertRaises(KeyError):
                get(store, key, "nonexistent")

    def test_secret_store_rejects_symlink_key(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "key"
            store = Path(d) / "secrets"
            generate_key(key)
            sym_key = Path(d) / "sym_key"
            os.symlink(key, sym_key)

            with self.assertRaises(ValueError):
                put(store, sym_key, "k", "v")

    def test_sbom_digest_and_symlink_exclusion(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a.txt").write_text("hello")
            (root / "b.txt").write_text("world")

            # Create a symlink which should be ignored in SBOM
            os.symlink(root / "a.txt", root / "sym.txt")

            result = sbom(root)
            paths = [c["path"] for c in result["components"]]
            self.assertIn("a.txt", paths)
            self.assertIn("b.txt", paths)
            self.assertNotIn("sym.txt", paths)

    def test_write_sbom_creates_valid_json(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "src"
            root.mkdir()
            (root / "app.py").write_text("print(1)")
            out_file = Path(d) / "sbom.json"

            write_sbom(root, out_file)
            self.assertTrue(out_file.is_file())
            parsed = json.loads(out_file.read_text())
            self.assertEqual(parsed["bomFormat"], "CycloneDX")
            self.assertEqual(len(parsed["components"]), 1)
