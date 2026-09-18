"""Encrypted local secret store using Fernet authenticated encryption."""
import json, os
from pathlib import Path
from cryptography.fernet import Fernet

def _atomic_write(path, data, mode=0o600):
    p=Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    fd=os.open(p, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0), mode)
    with os.fdopen(fd,'wb') as f: f.write(data)

def generate_key(path):
    _atomic_write(path, Fernet.generate_key())
def put(store,key,name,value):
    if not name or not isinstance(value,str): raise ValueError('name and string value are required')
    key_data=Path(key).read_bytes(); payload={}
    target=Path(store)
    if target.exists(): payload=json.loads(Fernet(key_data).decrypt(target.read_bytes()))
    payload[name]=value
    encrypted=Fernet(key_data).encrypt(json.dumps(payload,sort_keys=True).encode())
    tmp=target.with_name('.'+target.name+'.tmp')
    fd=os.open(tmp, os.O_WRONLY|os.O_CREAT|os.O_TRUNC|getattr(os,'O_NOFOLLOW',0), 0o600)
    with os.fdopen(fd,'wb') as f: f.write(encrypted); f.flush(); os.fsync(f.fileno())
    os.replace(tmp,target); os.chmod(target,0o600)
def get(store,key,name):
    payload=json.loads(Fernet(Path(key).read_bytes()).decrypt(Path(store).read_bytes()))
    return payload[name]
def names(store,key):
    return sorted(json.loads(Fernet(Path(key).read_bytes()).decrypt(Path(store).read_bytes())))
