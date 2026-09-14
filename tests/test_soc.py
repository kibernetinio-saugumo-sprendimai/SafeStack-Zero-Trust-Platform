import unittest
from zt.soc import detect, validate_event
class SocTests(unittest.TestCase):
 def test_brute_force_rule(self):
  events=[{'kind':'authentication','subject':'alice','success':False,'source':'vpn','timestamp':'now'} for _ in range(5)]
  self.assertEqual(detect(events)[0]['type'],'brute_force_suspected')
 def test_schema(self): self.assertTrue(validate_event({'kind':'x'}))
