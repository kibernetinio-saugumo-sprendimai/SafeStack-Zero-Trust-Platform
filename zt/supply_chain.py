"""Dependency-free SBOM and artifact digest helpers."""
import hashlib, json
from pathlib import Path

def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()
def sbom(root):
    root=Path(root); files=[]
    for path in sorted(root.rglob('*')):
        if path.is_file() and '.git' not in path.parts and '__pycache__' not in path.parts:
            files.append({'path':str(path.relative_to(root)),'sha256':digest(path),'size':path.stat().st_size})
    return {'bomFormat':'CycloneDX','specVersion':'1.5','components':files}
def write_sbom(root,out): Path(out).write_text(json.dumps(sbom(root),indent=2)+'\n',encoding='utf-8')
