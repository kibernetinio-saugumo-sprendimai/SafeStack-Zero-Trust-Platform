"""Strict, dependency-free policy-as-code loader and validator."""
import json
from pathlib import Path
REQUIRED = {'id','effect','subject','resource','action','min_posture'}
VALID = {'allow','deny'}
POSTURES = {'unknown','degraded','compliant'}
def validate_policy(policy):
    errors=[]
    if not isinstance(policy, dict): return ['policy must be an object']
    missing=REQUIRED-set(policy)
    if missing: errors.append('missing: '+','.join(sorted(missing)))
    if policy.get('effect') not in VALID: errors.append('effect must be allow or deny')
    if policy.get('min_posture') not in POSTURES: errors.append('min_posture is invalid')
    for field in ('id','subject','resource','action'):
        if field in policy and (not isinstance(policy[field],str) or not policy[field].strip()): errors.append(field+' must be a non-empty string')
    return errors
def load(path):
    data=json.loads(Path(path).read_text(encoding='utf-8'))
    policies=data.get('policies') if isinstance(data,dict) else data
    if not isinstance(policies,list): raise ValueError('policy document must contain a policies list')
    errors=[]
    for i,item in enumerate(policies):
        for error in validate_policy(item): errors.append(f'policies[{i}]: {error}')
    if errors: raise ValueError('; '.join(errors))
    return policies
