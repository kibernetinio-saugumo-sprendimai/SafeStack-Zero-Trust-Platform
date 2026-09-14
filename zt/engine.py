from datetime import datetime, timezone
from .store import Store
POSTURE = {'unknown':0,'degraded':1,'compliant':2}
class Decision:
    def __init__(self, allowed, reason, device_id, subject, resource, action): self.allowed=allowed; self.reason=reason; self.device_id=device_id; self.subject=subject; self.resource=resource; self.action=action
    def as_dict(self): return {'allowed':self.allowed,'reason':self.reason,'device_id':self.device_id,'subject':self.subject,'resource':self.resource,'action':self.action}
def evaluate(store: Store, device_id, subject, resource, action):
    device=store.device(device_id)
    if not device: return Decision(False,'device_not_registered',device_id,subject,resource,action)
    policies=store.policies(subject,resource,action)
    if not policies: result=Decision(False,'no_matching_policy',device_id,subject,resource,action)
    else:
        result=Decision(False,'default_deny',device_id,subject,resource,action)
        for p in policies:
            if POSTURE.get(device['posture'],0) < POSTURE.get(p['min_posture'],99): result=Decision(False,'device_posture_below_policy',device_id,subject,resource,action); break
            if p['effect']=='deny': result=Decision(False,'explicit_deny',device_id,subject,resource,action); break
            if p['effect']=='allow': result=Decision(True,'policy_allow',device_id,subject,resource,action); break
    store.decision((device_id,subject,resource,action,int(result.allowed),result.reason,datetime.now(timezone.utc).isoformat()))
    return result
