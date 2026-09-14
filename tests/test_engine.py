import tempfile, unittest
from zt.store import Store
from zt.engine import evaluate
class EngineTests(unittest.TestCase):
 def test_default_deny_and_allow(self):
  with tempfile.NamedTemporaryFile() as f:
   db=Store(f.name); db.add_device(('d1','laptop','alice','compliant','now'))
   self.assertFalse(evaluate(db,'d1','alice','vpn','connect').allowed)
   db.add_policy(('p1','allow','alice','vpn','connect','compliant'))
   self.assertTrue(evaluate(db,'d1','alice','vpn','connect').allowed)
 def test_posture_blocks(self):
  with tempfile.NamedTemporaryFile() as f:
   db=Store(f.name); db.add_device(('d1','laptop','alice','degraded','now')); db.add_policy(('p1','allow','alice','vpn','connect','compliant'))
   self.assertEqual(evaluate(db,'d1','alice','vpn','connect').reason,'device_posture_below_policy')
