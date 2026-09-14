"""Encrypted local secret store using Fernet authenticated encryption."""
import json, os
from pathlib import Path
from cryptography.fernet import Fernet

def generate_key(path):
    p=Path(path); p.write_bytes(Fernet.generate_key()); os.chmod(p,0o600)
def put(store,key,name,value):
    if not name or not isinstance(value,str): raise ValueError('name and string value are required')
    key_data=Path(key).read_bytes(); payload={}
    target=Path(store)
    if target.exists(): payload=json.loads(Fernet(key_data).decrypt(target.read_bytes()))
    payload[name]=value; target.write_bytes(Fernet(key_data).encrypt(json.dumps(payload,sort_keys=True).encode())); os.chmod(target,0o600)
def get(store,key,name):
    payload=json.loads(Fernet(Path(key).read_bytes()).decrypt(Path(store).read_bytes()))
    return payload[name]
def names(store,key):
    return sorted(json.loads(Fernet(Path(key).read_bytes()).decrypt(Path(store).read_bytes())))
