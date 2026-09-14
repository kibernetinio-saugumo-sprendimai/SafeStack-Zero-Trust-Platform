import tempfile, unittest
from zt.store import Store
from zt.identity import create_user, authenticate, assign_role, hash_password, verify_password
class IdentityTests(unittest.TestCase):
 def test_password_hash_and_auth(self):
  self.assertTrue(verify_password('a secure password',hash_password('a secure password')))
  self.assertFalse(verify_password('wrong password',hash_password('a secure password')))
  with tempfile.NamedTemporaryFile() as f:
   db=Store(f.name); create_user(db,'alice','a secure password'); assign_role(db,'alice','operator'); self.assertTrue(authenticate(db,'alice','a secure password')); self.assertFalse(authenticate(db,'alice','wrong password'))
 def test_short_password_rejected(self):
  with self.assertRaises(ValueError): hash_password('short')
