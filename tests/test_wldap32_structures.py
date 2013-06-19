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

from ctypes import string_at
import unittest

from wldap.wldap32_structures import LDAPMod, LDAP_BERVAL, LDAP_TIMEVAL


class Test_LDAP_BERVAL(unittest.TestCase):

    def test_from_value(self):
        val = b'bytes'
        res = LDAP_BERVAL.from_value(val)
        self.assertEqual(res.bv_len, 5)
        self.assertEqual(string_at(res.bv_val, 5), val)


class Test_LDAP_TIMEVAL(unittest.TestCase):

    def test_from_fractional_seconds_1(self):
        res = LDAP_TIMEVAL.from_fractional_seconds(0)
        self.assertEqual(res.tv_sec, 0)
        self.assertEqual(res.tv_usec, 0)

    def test_from_fractional_seconds_2(self):
        res = LDAP_TIMEVAL.from_fractional_seconds(1.3)
        self.assertEqual(res.tv_sec, 1)
        self.assertEqual(res.tv_usec, 300000)


class Test_LDAPMod(unittest.TestCase):

    def test_bad_args(self):
        self.assertRaises(ValueError, LDAPMod, 'op', 'attr')
