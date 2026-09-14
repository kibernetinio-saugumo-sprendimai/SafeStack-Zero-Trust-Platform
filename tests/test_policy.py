import json, tempfile, unittest
from zt.policy import load
class PolicyTests(unittest.TestCase):
 def test_valid_document(self):
  with tempfile.NamedTemporaryFile(mode='w+') as f:
   json.dump({'policies':[{'id':'p','effect':'deny','subject':'*','resource':'*','action':'*','min_posture':'unknown'}]},f); f.flush(); self.assertEqual(len(load(f.name)),1)
 def test_invalid_document(self):
  with tempfile.NamedTemporaryFile(mode='w+') as f:
   json.dump({'policies':[{'id':'p','effect':'permit'}]},f); f.flush()
   with self.assertRaises(ValueError): load(f.name)
