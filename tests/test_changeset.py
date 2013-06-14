# Copyright 2013 Arnaud Porterie
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ctypes import string_at, addressof
import unittest

# Mock is standard with Python 3.3 but is an external dependency with 2.x, and
# listed in requirements.txt as such.
try:
    from unittest import mock
except ImportError:
    import mock

# Wldap opens the wldap at import time, so we have to mock.patch early.
with mock.patch('ctypes.cdll'):
    import wldap

from wldap.wldap32_structures import LDAPMod


class TestChangeset(unittest.TestCase):

    def assertValidBinAttributes(self, attr, c_attr):
        for idx, item in enumerate(attr):
            c_bytes = string_at(c_attr[idx].contents.bv_val,
                                c_attr[idx].contents.bv_len)
            self.assertEqual(c_bytes, item)
        self.assertFalse(c_attr[len(attr)])

    def assertValidStrAttributes(self, attr, c_attr):
        for idx, item in enumerate(attr):
            self.assertEqual(c_attr[idx], item)
        self.assertFalse(c_attr[len(attr)])

    def _common_bin(self, fn, mod_op, attr, values):
        changeset = wldap.Changeset()
        fn(changeset, attr, values)
        self.assertEqual(len(changeset.changes), 1)

        op = changeset.changes[0]
        self.assertEqual(op.mod_op, mod_op | LDAPMod.LDAP_MOD_BVALUES)
        self.assertEqual(op.mod_type, attr)
        self.assertValidBinAttributes(values, op.mod_vals.modv_bvals)

        c_values = changeset.to_api_param()
        for idx, item in enumerate(changeset.changes):
            self.assertEqual(c_values[idx], addressof(item))
        self.assertEqual(c_values[len(changeset.changes)], None)

    def _common_str(self, fn, mod_op, attr, values):
        changeset = wldap.Changeset()
        fn(changeset, attr, values)
        self.assertEqual(len(changeset.changes), 1)

        op = changeset.changes[0]
        self.assertEqual(op.mod_op, mod_op)
        self.assertEqual(op.mod_type, attr)
        self.assertValidStrAttributes(values, op.mod_vals.modv_strvals)

        c_values = changeset.to_api_param()
        for idx, item in enumerate(changeset.changes):
            self.assertEqual(c_values[idx], addressof(item))
        self.assertEqual(c_values[len(changeset.changes)], None)

    def test_add(self):
        self._common_str(wldap.Changeset.add,
                         LDAPMod.LDAP_MOD_ADD,
                         'attr',
                         ['val1', 'val2'])

    def test_add_binary(self):
        self._common_bin(wldap.Changeset.add_binary,
                         LDAPMod.LDAP_MOD_ADD,
                         'attr',
                         [b'val1', b'val2'])

    def test_delete(self):
        self._common_str(wldap.Changeset.delete,
                         LDAPMod.LDAP_MOD_DELETE,
                         'attr',
                         ['val1', 'val2'])

    def test_delete_binary(self):
        self._common_bin(wldap.Changeset.delete_binary,
                         LDAPMod.LDAP_MOD_DELETE,
                         'attr',
                         [b'val1', b'val2'])

    def test_replace(self):
        self._common_str(wldap.Changeset.replace,
                         LDAPMod.LDAP_MOD_REPLACE,
                         'attr',
                         ['val1', 'val2'])

    def test_replace_binary(self):
        self._common_bin(wldap.Changeset.replace_binary,
                         LDAPMod.LDAP_MOD_REPLACE,
                         'attr',
                         [b'val1', b'val2'])

    def test_to_api_param_empty(self):
        changeset = wldap.Changeset()
        values = changeset.to_api_param()
        self.assertEqual(values, None)
