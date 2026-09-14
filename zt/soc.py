"""Small deterministic SOC event collector and detector."""
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
REQUIRED={'timestamp','kind','source','subject','success'}
def validate_event(event):
    if not isinstance(event,dict): return ['event must be an object']
    errors=['missing: '+k for k in sorted(REQUIRED-set(event))]
    if 'success' in event and not isinstance(event['success'],bool): errors.append('success must be boolean')
    return errors
def append_event(path,event):
    errors=validate_event(event)
    if errors: raise ValueError('; '.join(errors))
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('a',encoding='utf-8') as f: f.write(json.dumps(event,sort_keys=True)+'\n')
def detect(events, failed_threshold=5):
    failures=Counter(e.get('subject','unknown') for e in events if e.get('kind')=='authentication' and e.get('success') is False)
    alerts=[]
    for subject,count in failures.items():
        if count>=failed_threshold: alerts.append({'type':'brute_force_suspected','subject':subject,'count':count,'severity':'high'})
    for e in events:
        if e.get('kind')=='authorization' and e.get('reason') in ('device_not_registered','no_matching_policy'):
            alerts.append({'type':'unauthorized_access_attempt','subject':e.get('subject'),'source':e.get('source'),'severity':'medium'})
    return alerts
def read_events(path):
    rows=[]
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if line.strip(): rows.append(json.loads(line))
    return rows
