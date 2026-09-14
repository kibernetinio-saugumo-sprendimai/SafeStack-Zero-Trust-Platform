import tempfile, unittest
from pathlib import Path
from zt.secrets import generate_key, put, get, names
from zt.supply_chain import sbom
class SecurityModuleTests(unittest.TestCase):
 def test_secret_roundtrip(self):
  with tempfile.TemporaryDirectory() as d:
   key=Path(d)/'key'; store=Path(d)/'secrets'; generate_key(key); put(store,key,'api','value'); put(store,key,'second','two'); self.assertEqual(get(store,key,'api'),'value'); self.assertEqual(names(store,key),['api','second'])
 def test_sbom_digest(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); (root/'a.txt').write_text('hello'); result=sbom(root); self.assertEqual(result['components'][0]['size'],5); self.assertEqual(len(result['components'][0]['sha256']),64)
