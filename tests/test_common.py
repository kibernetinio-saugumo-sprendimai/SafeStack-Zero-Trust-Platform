"""Tests for common security filesystem utilities."""
import os
import tempfile
import unittest
from pathlib import Path
from zt.common import atomic_write, read_regular, resolve_parent, sha256_file


class CommonSecurityTests(unittest.TestCase):
    def test_atomic_write_creates_file_with_correct_permissions(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "secret.txt"
            atomic_write(target, b"secret data", mode=0o600)
            self.assertTrue(target.is_file())
            self.assertEqual(target.read_bytes(), b"secret data")
            mode = target.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_atomic_write_rejects_symlink_target(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            real_file = Path(tmp_dir) / "real.txt"
            real_file.write_bytes(b"initial")
            link = Path(tmp_dir) / "link.txt"
            os.symlink(real_file, link)

            with self.assertRaises(ValueError):
                atomic_write(link, b"overwrite attempt")

    def test_read_regular_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            real_file = Path(tmp_dir) / "real.txt"
            real_file.write_bytes(b"data")
            link = Path(tmp_dir) / "symlink.txt"
            os.symlink(real_file, link)

            with self.assertRaises(ValueError):
                read_regular(link)

    def test_read_regular_rejects_directories(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaises(ValueError):
                read_regular(tmp_dir)

    def test_sha256_file_streamed_hash(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "test.bin"
            file_path.write_bytes(b"hello world")
            expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            self.assertEqual(sha256_file(file_path), expected)

    def test_sha256_file_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "test.bin"
            file_path.write_bytes(b"data")
            link = Path(tmp_dir) / "link.bin"
            os.symlink(file_path, link)

            with self.assertRaises(ValueError):
                sha256_file(link)

    def test_resolve_parent_rejects_symlink_parent(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            real_dir = Path(tmp_dir) / "real_dir"
            real_dir.mkdir()
            symlink_dir = Path(tmp_dir) / "sym_dir"
            os.symlink(real_dir, symlink_dir)

            with self.assertRaises(ValueError):
                resolve_parent(symlink_dir / "target.txt")
