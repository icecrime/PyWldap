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

import unittest

# Mock is standard with Python 3.3 but is an external dependency with 2.x, and
# listed in requirements.txt as such.
try:
    from unittest import mock
except ImportError:
    import mock

from wldap.exceptions import LdapError
from wldap.wldap32_constants import ReturnCodes
from wldap.wldap32_dll import (errcheck_compare, errcheck_pointer,
                               errcheck_retcode, errcheck_sentinel)


class TestErrCheck(unittest.TestCase):

    def test_errcheck_compare_ok(self):
        result = ReturnCodes.LDAP_COMPARE_TRUE
        self.assertEqual(True, errcheck_compare(result, 'func', 'args'))

    def test_errcheck_compare_ko(self):
        result = ReturnCodes.LDAP_COMPARE_FALSE
        self.assertEqual(False, errcheck_compare(result, 'func', 'args'))

    def test_errcheck_compare_error(self):
        self.assertRaises(LdapError, errcheck_compare, 'dummy', 'func', 'args')

    def test_errcheck_pointer_ok(self):
        self.assertEqual(1, errcheck_pointer(1, 'func', 'args'))

    def test_errcheck_pointer_null_error(self):
        with mock.patch('wldap.wldap32_dll.LdapGetLastError') as m:
            m.return_value = ReturnCodes.LDAP_TIMEOUT
            self.assertRaises(LdapError, errcheck_pointer, 0, 'func', 'args')

    def test_errcheck_pointer_null_success(self):
        with mock.patch('wldap.wldap32_dll.LdapGetLastError') as m:
            m.return_value = ReturnCodes.LDAP_SUCCESS
            self.assertEqual(0, errcheck_pointer(0, 'func', 'args'),)

    def test_errcheck_retcode_ok(self):
        result = ReturnCodes.LDAP_SUCCESS
        self.assertEqual(result, errcheck_retcode(result, 'func', 'args'))

    def test_errcheck_retcode_ko(self):
        result = ReturnCodes.LDAP_TIMEOUT
        self.assertRaises(LdapError, errcheck_retcode, result, 'func', 'args')

    def test_errcheck_sentinel_ok(self):
        self.assertEqual(0, errcheck_sentinel(0, 'func', 'args'))

    def test_errcheck_sentinel_ko(self):
        self.assertRaises(LdapError, errcheck_sentinel, -1, 'func', 'args')
