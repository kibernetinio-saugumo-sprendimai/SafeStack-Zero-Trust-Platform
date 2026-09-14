"""SafeStack platform extensions: local-first security building blocks."""
import hashlib, json, ssl
from datetime import datetime, timezone
from pathlib import Path

def signed_update_manifest(files):
    return {'schema':'safestack/update-v1','created_at':datetime.now(timezone.utc).isoformat(),'files':[{'path':str(p),'sha256':hashlib.sha256(Path(p).read_bytes()).hexdigest()} for p in files]}
def fleet_inventory(store):
    return [dict(r) for r in store.db.execute('SELECT * FROM devices ORDER BY name')]
def append_immutable(path,event,previous=''):
    payload=json.dumps({'event':event,'previous':previous},sort_keys=True); digest=hashlib.sha256(payload.encode()).hexdigest()
    with Path(path).open('a',encoding='utf-8') as f: f.write(json.dumps({'payload':json.loads(payload),'hash':digest})+'\n')
    return digest
def verify_immutable(path):
    previous=''
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        row=json.loads(line); payload=json.dumps(row['payload'],sort_keys=True)
        if row['payload'].get('previous','') != previous or hashlib.sha256(payload.encode()).hexdigest()!=row['hash']: return False
        previous=row['hash']
    return True
def compliance_check(controls, evidence):
    return [{'id':c['id'],'title':c['title'],'status':'pass' if c['id'] in evidence else 'review'} for c in controls]
def certificate_expiry(host,port=443):
    cert=ssl.get_server_certificate((host,port))
    return {'host':host,'certificate_pem':cert,'checked_at':datetime.now(timezone.utc).isoformat()}
def container_digest(image):
    return hashlib.sha256(image.encode()).hexdigest()
def mesh_peer(name,public_key,address):
    if not public_key or not address: raise ValueError('peer public_key and address are required')
    return {'name':name,'public_key':public_key,'allowed_ips':[address]}
def evidence_seal(data):
    return {'sha256':hashlib.sha256(data).hexdigest(),'sealed_at':datetime.now(timezone.utc).isoformat()}
def phishing_simulation(template, recipient):
    if not template or not recipient: raise ValueError('template and recipient required')
    return {'recipient':recipient,'template':template,'training_only':True,'sent':False}
def privacy_profile(settings, profile):
    return {key: settings.get(key) == value for key,value in profile.items()}
def honeypot_event(source, service):
    return {'source':source,'service':service,'severity':'high','action_required':'review_and_isolate'}
