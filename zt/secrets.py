"""Encrypted local secret store using Fernet authenticated symmetric encryption."""
import json
from pathlib import Path
from typing import List, Union
from cryptography.fernet import Fernet
from .common import atomic_write, read_regular


def generate_key(path: Union[str, Path]) -> None:
    """Generate and write a new Fernet encryption key with 0600 permissions."""
    atomic_write(path, Fernet.generate_key(), mode=0o600)


def put(store: Union[str, Path], key: Union[str, Path], name: str, value: str) -> None:
    """Encrypt and store a secret value in the specified vault file."""
    if not name or not isinstance(name, str) or not name.strip():
        raise ValueError("name must be a non-empty string")
    if not isinstance(value, str):
        raise ValueError("string value is required")

    key_bytes = read_regular(key)
    fernet = Fernet(key_bytes)
    payload = {}

    target = Path(store).expanduser()
    if target.exists():
        raw_encrypted = read_regular(target)
        try:
            decrypted = fernet.decrypt(raw_encrypted)
            parsed = json.loads(decrypted.decode("utf-8"))
            if isinstance(parsed, dict):
                payload = parsed
            else:
                raise ValueError("Vault payload is not a valid JSON object")
        except Exception as err:
            raise ValueError(f"Failed to decrypt or parse vault: {err}") from err

    payload[name] = value
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    encrypted = fernet.encrypt(serialized)
    atomic_write(store, encrypted, mode=0o600)


def get(store: Union[str, Path], key: Union[str, Path], name: str) -> str:
    """Retrieve and decrypt a secret value by name from the vault."""
    key_bytes = read_regular(key)
    raw_encrypted = read_regular(store)
    fernet = Fernet(key_bytes)
    try:
        decrypted = fernet.decrypt(raw_encrypted)
        payload = json.loads(decrypted.decode("utf-8"))
    except Exception as err:
        raise ValueError(f"Failed to decrypt vault: {err}") from err

    if not isinstance(payload, dict):
        raise ValueError("Vault payload is not a valid JSON object")
    if name not in payload:
        raise KeyError(f"Secret '{name}' not found in vault")
    return payload[name]


def names(store: Union[str, Path], key: Union[str, Path]) -> List[str]:
    """List all secret names available in the encrypted store."""
    key_bytes = read_regular(key)
    raw_encrypted = read_regular(store)
    fernet = Fernet(key_bytes)
    try:
        decrypted = fernet.decrypt(raw_encrypted)
        payload = json.loads(decrypted.decode("utf-8"))
    except Exception as err:
        raise ValueError(f"Failed to decrypt vault: {err}") from err

    if not isinstance(payload, dict):
        raise ValueError("Vault payload is not a valid JSON object")
    return sorted(payload.keys())
