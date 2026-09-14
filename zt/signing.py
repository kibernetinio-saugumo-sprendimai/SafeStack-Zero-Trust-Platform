from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def keygen(private, public):
    sk=Ed25519PrivateKey.generate(); pk=sk.public_key(); open(private,'wb').write(sk.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())); os.chmod(private,0o600); open(public,'wb').write(pk.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
def sign(data, private):
    sk=serialization.load_pem_private_key(open(private,'rb').read(),password=None); return sk.sign(data)
def verify(data, signature, public):
    try: serialization.load_pem_public_key(open(public,'rb').read()).verify(signature,data); return True
    except Exception: return False
import os
