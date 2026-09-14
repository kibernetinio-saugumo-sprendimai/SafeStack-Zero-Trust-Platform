import tempfile, unittest
from pathlib import Path
from zt.extensions import append_immutable, verify_immutable, compliance_check, mesh_peer, evidence_seal, phishing_simulation
class ExtensionTests(unittest.TestCase):
 def test_hash_chain(self):
  with tempfile.NamedTemporaryFile() as f:
   previous=append_immutable(f.name,{'kind':'login'}); append_immutable(f.name,{'kind':'allow'},previous); self.assertTrue(verify_immutable(f.name)); Path(f.name).write_text(Path(f.name).read_text().replace('login','tampered')); self.assertFalse(verify_immutable(f.name))
 def test_safe_boundaries(self):
  self.assertEqual(compliance_check([{'id':'C1','title':'MFA'}],set())[0]['status'],'review'); self.assertEqual(mesh_peer('pi','pub','10.8.0.2/32')['name'],'pi'); self.assertFalse(phishing_simulation('training','a@example.com')['sent']); self.assertEqual(len(evidence_seal(b'x')['sha256']),64)
