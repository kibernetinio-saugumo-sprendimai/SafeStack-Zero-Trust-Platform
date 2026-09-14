import unittest
from zt.api import page, serve
class ApiTests(unittest.TestCase):
 def test_dashboard_escapes_data(self):
  out=page({'devices':[],'policies':[],'decisions':[{'subject':'<x>','resource':'r','allowed':0,'reason':'deny'}]})
  self.assertIn('&lt;x&gt;',out); self.assertIn('SafeStack',out)
 def test_remote_binding_requires_opt_in(self):
  with self.assertRaises(ValueError): serve('/tmp/zt-test.db','0.0.0.0',8787)
