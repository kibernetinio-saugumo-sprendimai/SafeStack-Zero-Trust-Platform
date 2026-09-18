import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def keygen(private, public):
    sk=Ed25519PrivateKey.generate(); pk=sk.public_key()
    _write_private(private, sk.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    _write_public(public, pk.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))

def _write_private(path, data):
    fd=os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0), 0o600)
    with os.fdopen(fd,'wb') as f: f.write(data)

def _write_public(path, data):
    fd=os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0), 0o644)
    with os.fdopen(fd,'wb') as f: f.write(data)
def sign(data, private):
    with open(private,'rb') as f: raw=f.read()
    sk=serialization.load_pem_private_key(raw,password=None); return sk.sign(data)
def verify(data, signature, public):
    try:
        with open(public,'rb') as f: raw=f.read()
        serialization.load_pem_public_key(raw).verify(signature,data); return True
    except Exception: return False
import os
