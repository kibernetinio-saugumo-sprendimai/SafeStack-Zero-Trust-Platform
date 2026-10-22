"""Common security and filesystem utilities for SafeStack Zero Trust Platform."""
import hashlib
import os
import tempfile
from pathlib import Path


def resolve_parent(path: str | Path) -> Path:
    """Ensure parent directory exists, is not a symlink, and return resolved Path."""
    target = Path(path).expanduser()
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink():
        raise ValueError(f"Parent directory must not be a symlink: {parent}")
    return parent.resolve(strict=True)


def read_regular(path: str | Path) -> bytes:
    """Read bytes from a regular file, strictly rejecting symlinks and special files."""
    target = Path(path).expanduser()
    if target.is_symlink():
        raise ValueError(f"Symlinks are prohibited for secure reading: {target}")
    if not target.is_file():
        raise ValueError(f"Expected a regular file: {target}")
    return target.read_bytes()


def atomic_write(path: str | Path, data: bytes, mode: int = 0o600) -> None:
    """Atomically write data to a file with strict permissions and fsync."""
    target = Path(path).expanduser()
    if target.is_symlink():
        raise ValueError(f"Target path must not be a symlink: {target}")
    parent = resolve_parent(target)
    dest = parent / target.name
    if dest.is_dir():
        raise ValueError(f"Target destination cannot be a directory: {dest}")

    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, dest)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def sha256_file(path: str | Path, chunk_size: int = 65536) -> str:
    """Streamed SHA-256 calculation for regular files, refusing symlinks."""
    target = Path(path).expanduser()
    if target.is_symlink() or not target.is_file():
        raise ValueError(f"Expected a regular, non-symlink file: {target}")
    hasher = hashlib.sha256()
    with open(target, "rb") as stream:
        while chunk := stream.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()
