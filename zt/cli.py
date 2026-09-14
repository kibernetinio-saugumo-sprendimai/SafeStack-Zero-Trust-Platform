import argparse, json, sys, uuid
from datetime import datetime, timezone
from .store import Store
from .engine import evaluate
from .signing import keygen
from .api import serve

def main(argv=None):
 p=argparse.ArgumentParser(prog='safestack-zt'); s=p.add_subparsers(dest='cmd',required=True)
 d=s.add_parser('device-add'); d.add_argument('--db',default='zero-trust.db'); d.add_argument('--id',default=None); d.add_argument('--name',required=True); d.add_argument('--owner',required=True); d.add_argument('--posture',choices=['unknown','degraded','compliant'],default='unknown')
 pol=s.add_parser('policy-add'); pol.add_argument('--db',default='zero-trust.db'); pol.add_argument('--id',default=None); pol.add_argument('--effect',choices=['allow','deny'],required=True); pol.add_argument('--subject',required=True); pol.add_argument('--resource',required=True); pol.add_argument('--action',required=True); pol.add_argument('--min-posture',choices=['unknown','degraded','compliant'],default='compliant')
 e=s.add_parser('authorize'); e.add_argument('--db',default='zero-trust.db'); e.add_argument('--device',required=True); e.add_argument('--subject',required=True); e.add_argument('--resource',required=True); e.add_argument('--action',required=True)
 k=s.add_parser('keygen'); k.add_argument('private'); k.add_argument('public'); v=s.add_parser('serve'); v.add_argument('--db',default='zero-trust.db'); v.add_argument('--host',default='127.0.0.1'); v.add_argument('--port',type=int,default=8787); v.add_argument('--allow-remote',action='store_true'); x=p.parse_args(argv)
 if x.cmd=='keygen': keygen(x.private,x.public); return 0
 if x.cmd=='serve': serve(x.db,x.host,x.port,x.allow_remote); return 0
 db=Store(x.db)
 if x.cmd=='device-add': db.add_device((x.id or str(uuid.uuid4()),x.name,x.owner,x.posture,datetime.now(timezone.utc).isoformat())); print('device registered'); return 0
 if x.cmd=='policy-add': db.add_policy((x.id or str(uuid.uuid4()),x.effect,x.subject,x.resource,x.action,x.min_posture)); print('policy registered'); return 0
 result=evaluate(db,x.device,x.subject,x.resource,x.action); print(json.dumps(result.as_dict(),indent=2)); return 0 if result.allowed else 2

if __name__ == '__main__':
 raise SystemExit(main())
