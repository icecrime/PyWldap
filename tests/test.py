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

import os
import unittest

# Mock is standard with Python 3.3 but is an external dependency with 2.x, and
# listed in requirements.txt as such.
try:
    from unittest import mock
except ImportError:
    import mock

# Wldap opens the dll at import time, so we have to mock.patch early.
with mock.patch('ctypes.cdll'):
    import wldap


@mock.patch('wldap.wldap32_dll._dll')
class TestWldap(unittest.TestCase):

    def test_ldap_init_default(self, dll):
        wldap.ldap()
        dll.ldap_init.assert_called_once_with(None, wldap.LDAP_PORT)

    def test_ldap_init_specific(self, dll):
        ldap_host, ldap_port = 'ldap://test', 4242
        wldap.ldap(ldap_host, ldap_port)
        dll.ldap_init.assert_called_once_with(ldap_host, ldap_port)

    def test_ldap_abandon(self, dll):
        self.validate_call_forwarding(dll, 'abandon', (os.urandom(64),))

    def test_ldap_bind(self, dll):
        self.validate_call_forwarding(dll, 'bind', ('dn', 'cred', 'method'))

    def test_ldap_bind_s(self, dll):
        self.validate_call_forwarding(dll, 'bind_s', ('dn', 'cred', 'method'))

    def test_ldap_search(self, dll):
        attr = ['attr1', 'attr2', 'attr3']
        self.validate_search(dll, 'search', attr, 'searchW')

    def test_ldap_search_s(self, dll):
        attr = ['attr1', 'attr2', 'attr3']
        self.validate_search(dll, 'search_s', attr, 'search_sW')

    def test_ldap_search_no_attrs(self, dll):
        attr = []
        self.validate_search(dll, 'search', attr, 'searchW')

    def test_ldap_search_s_no_attrs(self, dll):
        attr = []
        self.validate_search(dll, 'search_s', attr, 'search_sW')

    def test_ldap_simple_bind(self, dll):
        self.validate_call_forwarding(dll, 'simple_bind', ('dn', 'password'),
                                      'simple_bindW')

    def test_ldap_simple_bind_s(self, dll):
        self.validate_call_forwarding(dll, 'simple_bind_s', ('dn', 'password'),
                                      'simple_bind_sW')

    def test_ldap_unbind(self, dll):
        self.validate_call_forwarding(dll, 'unbind', ())

    def test_ldap_unbind_s(self, dll):
        self.validate_call_forwarding(dll, 'unbind_s', ())

    def validate_call_forwarding(self, dll, func, args, api_func=None):
        l = wldap.ldap()
        getattr(l, func)(*args)

        cfunc = getattr(dll, 'ldap_' + (api_func or func))
        cfunc.assert_called_once_with(mock.ANY, *args)

    def validate_search(self, dll, func, attr, api_func=None):
        args = ('base', 'scope', 'filt', attr, 'attronly')
        l = wldap.ldap()
        getattr(l, func)(*args)

        cfunc = dll.ldap_searchW
        cargs = ('base', 'scope', 'filt', mock.ANY, 'attronly', mock.ANY)
        cfunc.assert_called_once_with(mock.ANY, *cargs)
        self.assertSequenceEqual(cfunc.call_args[0][4], attr + [None])


if __name__ == "__main__":
    unittest.main()
