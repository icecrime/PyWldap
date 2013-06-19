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

from ctypes import cast
import os
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
from wldap.exceptions import LdapError
from wldap.wldap32_structures import LDAP_TIMEVAL, LDAPMod


@mock.patch('wldap.wldap32_dll.dll')
class TestWldap(unittest.TestCase):

    def assert_forward(self, dll, func, args, api_func=None):
        l = wldap.ldap()
        getattr(l, func)(*args)
        cfunc = getattr(dll, 'ldap_' + (api_func or func))
        cfunc.assert_called_once_with(mock.ANY, *args)

    def assertValidAttributes(self, attr, c_attr):
        for idx, item in enumerate(attr):
            self.assertEqual(c_attr[idx], item)
        self.assertEqual(c_attr[len(attr)], None)

    def test_ldap_init_default(self, dll):
        wldap.ldap()
        dll.ldap_initW.assert_called_once_with(None, wldap.LDAP_PORT)

    def test_ldap_init_specific(self, dll):
        ldap_host, ldap_port = 'ldap://test', 4242
        wldap.ldap(ldap_host, ldap_port)
        dll.ldap_initW.assert_called_once_with(ldap_host, ldap_port)

    def test_ldap_abandon(self, dll):
        self.assert_forward(dll, 'abandon', (os.urandom(64),))

    def test_ldap_add(self, dll):
        l = wldap.ldap()
        l.add('dn', ('attr1', ['val1']), ('attr2', ['val2.1', 'val2.2']))
        dll.ldap_addW.assert_called_once_with(l._l, 'dn', mock.ANY)

        mods = dll.ldap_addW.call_args[0][2]
        self.assertEqual(mods[0].contents.mod_op, LDAPMod.LDAP_MOD_ADD)
        self.assertEqual(mods[0].contents.mod_type, 'attr1')
        self.assertEqual(mods[0].contents.mod_vals.modv_strvals[0], 'val1')
        self.assertEqual(mods[0].contents.mod_vals.modv_strvals[1], None)

        self.assertEqual(mods[1].contents.mod_op, LDAPMod.LDAP_MOD_ADD)
        self.assertEqual(mods[1].contents.mod_type, 'attr2')
        self.assertEqual(mods[1].contents.mod_vals.modv_strvals[0], 'val2.1')
        self.assertEqual(mods[1].contents.mod_vals.modv_strvals[1], 'val2.2')
        self.assertEqual(mods[1].contents.mod_vals.modv_strvals[2], None)

        self.assertEqual(mods[2], None)

    def test_ldap_add_s(self, dll):
        l = wldap.ldap()
        l.add_s('dn', ('attr1', ['val1']), ('attr2', ['val2.1', 'val2.2']))
        dll.ldap_add_sW.assert_called_once_with(l._l, 'dn', mock.ANY)

        mods = dll.ldap_add_sW.call_args[0][2]
        self.assertEqual(mods[0].contents.mod_op, LDAPMod.LDAP_MOD_ADD)
        self.assertEqual(mods[0].contents.mod_type, 'attr1')
        self.assertEqual(mods[0].contents.mod_vals.modv_strvals[0], 'val1')
        self.assertEqual(mods[0].contents.mod_vals.modv_strvals[1], None)

        self.assertEqual(mods[1].contents.mod_op, LDAPMod.LDAP_MOD_ADD)
        self.assertEqual(mods[1].contents.mod_type, 'attr2')
        self.assertEqual(mods[1].contents.mod_vals.modv_strvals[0], 'val2.1')
        self.assertEqual(mods[1].contents.mod_vals.modv_strvals[1], 'val2.2')
        self.assertEqual(mods[1].contents.mod_vals.modv_strvals[2], None)

        self.assertEqual(mods[2], None)

    def test_ldap_bind(self, dll):
        self.assert_forward(dll, 'bind', ('dn', 'cred', 'method'), 'bindW')

    def test_ldap_bind_s(self, dll):
        self.assert_forward(dll, 'bind_s', ('dn', 'cred', 'method'), 'bind_sW')

    def test_ldap_check_filter(self, dll):
        l = wldap.ldap()
        l.check_filter('filt')
        dll.ldap_check_filterW.assert_called_once_with(l._l, 'filt')

    def test_ldap_check_filter_ko(self, dll):
        dll.ldap_err2string.return_value = 'test'
        exc = LdapError(0)
        dll.ldap_check_filterW.side_effect = exc

        l = wldap.ldap()
        self.assertEqual(l.check_filter('filt'), exc)
        dll.ldap_check_filterW.assert_called_once_with(l._l, 'filt')

    def test_ldap_connect(self, dll):
        l = wldap.ldap()
        l.connect(None)
        dll.ldap_connect.assert_called_once_with(l._l, None)

    def test_ldap_delete(self, dll):
        l = wldap.ldap()
        l.delete('dn')
        dll.ldap_deleteW.assert_called_once_with(l._l, 'dn')

    def test_ldap_delete_s(self, dll):
        l = wldap.ldap()
        l.delete_s('dn')
        dll.ldap_delete_sW.assert_called_once_with(l._l, 'dn')

    def test_ldap_modify(self, dll):
        changeset = wldap.Changeset()
        changeset.replace('attr1', ['val1'])
        changeset.add('attr2', ['val2.1', 'val2.2'])

        l = wldap.ldap()
        l.modify('dn', changeset)
        dll.ldap_modifyW.assert_called_once_with(l._l, 'dn', mock.ANY)

        mods = dll.ldap_modifyW.call_args[0][2]
        self.assertEqual(mods[0].contents.mod_op, LDAPMod.LDAP_MOD_REPLACE)
        self.assertEqual(mods[0].contents.mod_type, 'attr1')
        self.assertEqual(mods[0].contents.mod_vals.modv_strvals[0], 'val1')
        self.assertEqual(mods[0].contents.mod_vals.modv_strvals[1], None)

        self.assertEqual(mods[1].contents.mod_op, LDAPMod.LDAP_MOD_ADD)
        self.assertEqual(mods[1].contents.mod_type, 'attr2')
        self.assertEqual(mods[1].contents.mod_vals.modv_strvals[0], 'val2.1')
        self.assertEqual(mods[1].contents.mod_vals.modv_strvals[1], 'val2.2')
        self.assertEqual(mods[1].contents.mod_vals.modv_strvals[2], None)

        self.assertEqual(mods[2], None)

    def test_ldap_modify_s(self, dll):
        changeset = wldap.Changeset()
        changeset.replace('attr1', ['val1'])
        changeset.add('attr2', ['val2.1', 'val2.2'])

        l = wldap.ldap()
        l.modify_s('dn', changeset)
        dll.ldap_modify_sW.assert_called_once_with(l._l, 'dn', mock.ANY)

        mods = dll.ldap_modify_sW.call_args[0][2]
        self.assertEqual(mods[0].contents.mod_op, LDAPMod.LDAP_MOD_REPLACE)
        self.assertEqual(mods[0].contents.mod_type, 'attr1')
        self.assertEqual(mods[0].contents.mod_vals.modv_strvals[0], 'val1')
        self.assertEqual(mods[0].contents.mod_vals.modv_strvals[1], None)

        self.assertEqual(mods[1].contents.mod_op, LDAPMod.LDAP_MOD_ADD)
        self.assertEqual(mods[1].contents.mod_type, 'attr2')
        self.assertEqual(mods[1].contents.mod_vals.modv_strvals[0], 'val2.1')
        self.assertEqual(mods[1].contents.mod_vals.modv_strvals[1], 'val2.2')
        self.assertEqual(mods[1].contents.mod_vals.modv_strvals[2], None)

        self.assertEqual(mods[2], None)

    def test_ldap_result_timeout(self, dll):
        l = wldap.ldap()
        l.result(0, 0, 1.3)
        dll.ldap_result.assert_called_once_with(l._l, 0, 0, mock.ANY, mock.ANY)

        timeval = cast(dll.ldap_result.call_args[0][3], LDAP_TIMEVAL.pointer)
        self.assertEqual(timeval.contents.tv_sec, 1)
        self.assertEqual(timeval.contents.tv_usec, 300000)

    def test_ldap_result_timeout_infinite(self, dll):
        l = wldap.ldap()
        l.result(0, 0, None)
        dll.ldap_result.assert_called_once_with(l._l, 0, 0, mock.ANY, mock.ANY)

        timeval = dll.ldap_result.call_args[0][3]
        self.assertEqual(timeval, None)

    def test_ldap_search(self, dll):
        attr = ['a1', 'a2']
        fn = dll.ldap_searchW

        l = wldap.ldap()
        l.search('base', 'sc', 'fi', attr, True)
        fn.assert_called_once_with(l._l, 'base', 'sc', 'fi', mock.ANY, True)
        self.assertValidAttributes(attr, fn.call_args[0][4])

    def test_ldap_search_s(self, dll):
        attr = ['a1', 'a2']
        fn = dll.ldap_search_sW

        l = wldap.ldap()
        l.search_s('base', 'sc', 'fi', attr, True)
        fn.assert_called_once_with(l._l, 'base', 'sc', 'fi', mock.ANY, True, mock.ANY)
        self.assertValidAttributes(attr, fn.call_args[0][4])

    def test_ldap_search_no_attrs(self, dll):
        fn = dll.ldap_searchW

        l = wldap.ldap()
        l.search('base', 'sc', 'fi', [], True)
        fn.assert_called_once_with(l._l, 'base', 'sc', 'fi', mock.ANY, True)
        self.assertValidAttributes([], fn.call_args[0][4])

    def test_ldap_search_s_no_attrs(self, dll):
        fn = dll.ldap_search_sW

        l = wldap.ldap()
        l.search_s('base', 'sc', 'fi', [], True)
        fn.assert_called_once_with(l._l, 'base', 'sc', 'fi', mock.ANY, True, mock.ANY)
        self.assertValidAttributes([], fn.call_args[0][4])

    def test_ldap_simple_bind(self, dll):
        args = ('dn', 'password')
        self.assert_forward(dll, 'simple_bind', args, 'simple_bindW')

    def test_ldap_simple_bind_s(self, dll):
        args = ('dn', 'password')
        self.assert_forward(dll, 'simple_bind_s', args, 'simple_bind_sW')

    def test_ldap_unbind(self, dll):
        self.assert_forward(dll, 'unbind', ())

    def test_ldap_unbind_s(self, dll):
        self.assert_forward(dll, 'unbind_s', ())
