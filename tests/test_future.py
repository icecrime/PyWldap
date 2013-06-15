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

import time
import unittest

# Mock is standard with Python 3.3 but is an external dependency with 2.x, and
# listed in requirements.txt as such.
try:
    from unittest import mock
except ImportError:
    import mock

from wldap.exceptions import TimeoutError
from wldap.future import Future


class TestFuture(unittest.TestCase):

    def test_cancel(self):
        ldap = mock.Mock()
        ldap.abandon.return_value = True

        future = Future(ldap, 0)
        self.assertEqual(True, future.cancel())
        ldap.abandon.assert_called_one_with(0)

    def test_cancelled(self):
        ldap = mock.Mock()
        ldap.abandon.return_value = True

        future = Future(ldap, 0)
        self.assertEqual(False, future.cancelled())
        self.assertEqual(True, future.cancel())
        self.assertEqual(True, future.cancelled())

    def test_exception(self):
        excp = ValueError('test')
        ldap = mock.Mock()
        ldap.result.side_effect = excp

        future = Future(ldap, 0)
        self.assertEqual(excp, future.exception())

    def test_exception_timeout(self):
        ldap = mock.Mock()
        ldap.result.return_value = None

        future = Future(ldap, 0)
        self.assertRaises(TimeoutError, future.exception, 0)

    def test_done(self):
        ldap = mock.Mock()
        ldap.result.side_effect = [None, None, 0]

        future = Future(ldap, 0)
        self.assertEqual(False, future.done())
        self.assertEqual(False, future.done())
        self.assertEqual(True, future.done())
        self.assertEqual(True, future.done())
        ldap.result.call_count = 3

    def test_result_exception(self):
        excp = ValueError('test')
        ldap = mock.Mock()
        ldap.result.side_effect = excp

        future = Future(ldap, 0)
        self.assertRaises(ValueError, future.result, 0)

    def test_result_timeout(self):
        ldap = mock.Mock()
        ldap.result.return_value = None

        future = Future(ldap, 0)
        self.assertRaises(TimeoutError, future.result, 0)

    def test_result_timeout_default(self):
        ldap = mock.Mock()
        ldap.result.return_value = 0

        future = Future(ldap, 0)
        self.assertEqual(0, future.result())
        ldap.result.assert_called_one_with(0, 1, None)

    def test_result_timeout_zero(self):
        ldap = mock.Mock()
        ldap.result.return_value = 0

        future = Future(ldap, 0)
        self.assertEqual(0, future.result(0))
        ldap.result.assert_called_one_with(0, 1, 0)

    def test_result_multiple(self):
        ldap = mock.Mock()
        ldap.result.return_value = 0

        future = Future(ldap, 0)
        self.assertEqual(0, future.result(0))
        self.assertEqual(0, future.result(0))
        self.assertEqual(0, future.result(0))
        ldap.result.assert_called_one_with(0, 1, 0)

    def test_running(self):
        self.assertEqual(False, Future(mock.Mock(), 0).running())
