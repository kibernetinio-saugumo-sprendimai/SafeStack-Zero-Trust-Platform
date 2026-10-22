"""Dependency-free Software Bill of Materials (SBOM) and artifact digest helpers."""
import json
from pathlib import Path
from typing import Any, Dict, Union
from .common import atomic_write, sha256_file


def digest(path: Union[str, Path]) -> str:
    """Calculate the streamed SHA-256 digest of a regular file."""
    return sha256_file(path)


def sbom(root_dir: Union[str, Path]) -> Dict[str, Any]:
    """Generate a CycloneDX v1.5 compliant SBOM for files under root directory."""
    root = Path(root_dir).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Root path must be a valid directory: {root}")

    files = []
    ignored_parts = {".git", "__pycache__", ".venv", ".tox", ".eggs"}

    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            continue
        if any(part in ignored_parts for part in path.parts):
            continue
        if path.is_file():
            rel_path = str(path.relative_to(root))
            files.append({
                "path": rel_path,
                "sha256": digest(path),
                "size": path.stat().st_size,
            })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": files,
    }


def write_sbom(root_dir: Union[str, Path], output_path: Union[str, Path]) -> None:
    """Write an SBOM atomically with 0644 permissions to prevent symlink race conditions."""
    bom_data = sbom(root_dir)
    payload = (json.dumps(bom_data, indent=2) + "\n").encode("utf-8")
    atomic_write(output_path, payload, mode=0o644)
