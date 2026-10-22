"""SafeStack platform extensions: local-first security building blocks."""
import hashlib
import ipaddress
import json
import os
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Set, Union
from .common import read_regular, resolve_parent, sha256_file
from .store import Store


def signed_update_manifest(files: Iterable[Union[str, Path]]) -> Dict[str, Any]:
    """Generate an update manifest with streamed SHA-256 file hashes, rejecting symlinks."""
    file_entries = []
    for p in files:
        target = Path(p)
        file_entries.append({
            "path": str(target),
            "sha256": sha256_file(target),
        })

    return {
        "schema": "safestack/update-v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": file_entries,
    }


def fleet_inventory(store: Store) -> List[Dict[str, Any]]:
    """Retrieve all enrolled devices ordered by name."""
    rows = store.db.execute("SELECT * FROM devices ORDER BY name").fetchall()
    return [dict(r) for r in rows]


def append_immutable(path: Union[str, Path], event: Any, previous: str = "") -> str:
    """Append a tamper-evident, cryptographically chained event record (0600 mode)."""
    target = Path(path).expanduser()
    if target.is_symlink():
        raise ValueError(f"Target immutable log cannot be a symlink: {target}")

    resolve_parent(target)
    payload_dict = {"event": event, "previous": previous}
    payload_str = json.dumps(payload_dict, sort_keys=True)
    digest = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

    line_content = json.dumps({"payload": payload_dict, "hash": digest}, sort_keys=True) + "\n"

    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line_content)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        raise

    return digest


def verify_immutable(path: Union[str, Path]) -> bool:
    """Verify hash-chain integrity of an immutable log file, refusing symlinks."""
    try:
        content = read_regular(path).decode("utf-8")
    except Exception:
        return False

    previous = ""
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
            if not isinstance(row, dict) or "payload" not in row or "hash" not in row:
                return False
            payload = row["payload"]
            if not isinstance(payload, dict):
                return False
            if payload.get("previous", "") != previous:
                return False
            payload_str = json.dumps(payload, sort_keys=True)
            recalculated = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
            if recalculated != row["hash"]:
                return False
            previous = row["hash"]
        except Exception:
            return False
    return True


def compliance_check(controls: Sequence[Dict[str, str]], evidence: Set[str]) -> List[Dict[str, str]]:
    """Evaluate controls against collected evidence IDs."""
    return [
        {
            "id": c["id"],
            "title": c.get("title", ""),
            "status": "pass" if c["id"] in evidence else "review",
        }
        for c in controls
    ]


def certificate_expiry(host: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    """Retrieve server TLS certificate in read-only mode with timeout."""
    if not host or not isinstance(host, str):
        raise ValueError("host must be a non-empty string")
    cert = ssl.get_server_certificate((host, port), timeout=timeout)
    return {
        "host": host,
        "certificate_pem": cert,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def container_digest(image: str) -> str:
    """Generate deterministic SHA-256 container identifier."""
    if not image or not isinstance(image, str):
        raise ValueError("image must be a non-empty string")
    return hashlib.sha256(image.encode("utf-8")).hexdigest()


def mesh_peer(name: str, public_key: str, address: str) -> Dict[str, Any]:
    """Create validated WireGuard peer configuration dictionary."""
    if not name or not isinstance(name, str):
        raise ValueError("peer name is required")
    if not public_key or not isinstance(public_key, str):
        raise ValueError("peer public_key is required")
    if not address or not isinstance(address, str):
        raise ValueError("peer address is required")

    # Validate IP address / network CIDR format
    try:
        ipaddress.ip_network(address, strict=False)
    except ValueError as err:
        raise ValueError(f"Invalid peer address format: {address}") from err

    return {
        "name": name,
        "public_key": public_key,
        "allowed_ips": [address],
    }


def evidence_seal(data: Union[str, bytes]) -> Dict[str, str]:
    """Create a tamper-evident SHA-256 seal for arbitrary digital evidence."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sealed_at": datetime.now(timezone.utc).isoformat(),
    }


def phishing_simulation(template: str, recipient: str) -> Dict[str, Any]:
    """Generate training-only phishing awareness object without sending network traffic."""
    if not template or not recipient:
        raise ValueError("template and recipient required")
    return {
        "recipient": recipient,
        "template": template,
        "training_only": True,
        "sent": False,
    }


def privacy_profile(settings: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, bool]:
    """Compare system privacy settings against target hardening profile."""
    return {key: settings.get(key) == value for key, value in profile.items()}


def honeypot_event(source: str, service: str) -> Dict[str, str]:
    """Format honeypot intrusion detection event."""
    return {
        "source": source,
        "service": service,
        "severity": "high",
        "action_required": "review_and_isolate",
    }
