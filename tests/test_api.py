import unittest
from zt.api import page
class ApiTests(unittest.TestCase):
 def test_dashboard_escapes_data(self):
  out=page({'devices':[],'policies':[],'decisions':[{'subject':'<x>','resource':'r','allowed':0,'reason':'deny'}]})
  self.assertIn('&lt;x&gt;',out); self.assertIn('SafeStack',out)
