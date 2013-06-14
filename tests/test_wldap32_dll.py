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

from wldap.exceptions import LdapError
from wldap.wldap32_constants import ReturnCodes
from wldap.wldap32_dll import errcheck_compare, errcheck_pointer


class TestErrCheck(unittest.TestCase):

    def test_errcheck_compare_ok(self):
        result = ReturnCodes.LDAP_COMPARE_TRUE
        ret = errcheck_compare(result, 'func', 'args')
        self.assertEqual(ret, True)

    def test_errcheck_compare_ko(self):
        result = ReturnCodes.LDAP_COMPARE_FALSE
        ret = errcheck_compare(result, 'func', 'args')
        self.assertEqual(ret, False)

    def test_errcheck_compare_error(self):
        self.assertRaises(LdapError, errcheck_compare, 'dummy', 'func', 'args')

    def test_errcheck_pointer_ok(self):
        ret = errcheck_pointer(0x01, 'func', 'args')
        self.assertEqual(ret, 0x01)
