"""Ed25519 asymmetric signing and verification for SafeStack Zero Trust."""
import os
from pathlib import Path
from typing import Union
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from .common import atomic_write, read_regular


def keygen(private_path: Union[str, Path], public_path: Union[str, Path]) -> None:
    """Generate a new Ed25519 keypair and write private (0600) and public (0644) keys."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    atomic_write(private_path, priv_pem, mode=0o600)
    atomic_write(public_path, pub_pem, mode=0o644)


def sign(data: Union[str, bytes], private_key_path: Union[str, Path]) -> bytes:
    """Sign data using an Ed25519 private key file."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    raw_key = read_regular(private_key_path)
    loaded_key = serialization.load_pem_private_key(raw_key, password=None)
    if not isinstance(loaded_key, Ed25519PrivateKey):
        raise TypeError("Expected an Ed25519 private key")
    return loaded_key.sign(data)


def verify(data: Union[str, bytes], signature: bytes, public_key_path: Union[str, Path]) -> bool:
    """Verify an Ed25519 signature against data and a public key file."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    try:
        raw_key = read_regular(public_key_path)
        loaded_key = serialization.load_pem_public_key(raw_key)
        if not isinstance(loaded_key, Ed25519PublicKey):
            return False
        loaded_key.verify(signature, data)
        return True
    except Exception:
        return False
