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

from ctypes import create_string_buffer
import unittest

# Mock is standard with Python 3.3 but is an external dependency with 2.x, and
# listed in requirements.txt as such.
try:
    from unittest import mock
except ImportError:
    import mock

from wldap.message import Message, MessageAttribute, MessageEntry
from wldap.message import parse_binary_message, parse_message


@mock.patch('wldap.wldap32_dll.dll')
class TestMessage(unittest.TestCase):

    def test_binary_values(self, dll):
        ret_1 = mock.Mock()
        ret_1.contents.bv_len = 2
        ret_1.contents.bv_val = create_string_buffer(b'v1___')
        ret_2 = mock.Mock()
        ret_2.contents.bv_len = 4
        ret_2.contents.bv_val = create_string_buffer(b'val2___')
        dll.ldap_get_values_lenW.return_value = [ret_1, ret_2, None]

        mock_l = mock.Mock()
        mock_m = mock.Mock()
        msg_attrb = MessageAttribute(mock_l, mock_m, 'name')
        self.assertEqual(list(msg_attrb.binary_values), [b'v1', b'val2'])

    def test_entry_get_attribute(self, dll):
        dll.ldap_get_valuesW.return_value = ['dummy']

        mock_l = mock.Mock()
        mock_m = mock.Mock()
        msg_entry = MessageEntry(mock_l, mock_m)
        msg_attrb = msg_entry['test']
        self.assertEqual(msg_attrb.name, 'test')
        self.assertEqual(list(msg_attrb.values), ['dummy'])

    def test_message(self, dll):
        mock_l = mock.Mock()
        mock_m = mock.Mock()
        message = Message(mock_l, mock_m)

        dll.ldap_count_entries.return_value = 42
        self.assertEqual(42, len(message))
        dll.ldap_count_entries.assert_called_once_with(mock_l, mock_m)

        del message
        dll.ldap_msg_free.called_once_with(mock_m)

    def test_message_iter(self, dll):
        dll.ldap_count_entries.return_value = 3
        dll.ldap_first_entry.return_value = 1
        dll.ldap_next_entry.side_effect = [2, 3, None]

        mock_l = mock.Mock()
        mock_m = mock.Mock()
        message = Message(mock_l, mock_m)
        self.assertEqual(len(message), 3)
        self.assertEqual(sum(1 for item in message), 3)

    def test_message_entry_iter(self, dll):
        dll.ldap_count_entries.return_value = 3
        dll.ldap_first_attributeW.return_value = 1
        dll.ldap_next_attributeW.side_effect = [2, 3, None]

        mock_l = mock.Mock()
        mock_m = mock.Mock()
        msg_entry = MessageEntry(mock_l, mock_m)
        self.assertEqual(len(msg_entry), 3)
        self.assertEqual(sum(1 for item in msg_entry), 3)

    def test_parse_message(self, dll):
        dll.ldap_first_entry.return_value = 'entry_1'
        dll.ldap_next_entry.side_effect = ['entry_2', None]
        dll.ldap_first_attributeW.side_effect = [1, 3]
        dll.ldap_next_attributeW.side_effect = [2, None, 4, None]
        dll.ldap_get_valuesW.side_effect = [['1.1'], ['1.2', '1.3'], None, ['4']]

        expects = [{1: ['1.1'], 2: ['1.2', '1.3']}, {3: [], 4: ['4']}]

        mock_l = mock.Mock()
        mock_m = mock.Mock()
        message = Message(mock_l, mock_m)
        self.assertEqual(parse_message(message), expects)

    def test_parse_message_binary(self, dll):
        dll.ldap_first_entry.return_value = 'entry_1'
        dll.ldap_next_entry.side_effect = ['entry_2', None]
        dll.ldap_first_attributeW.side_effect = [1, 3]
        dll.ldap_next_attributeW.side_effect = [2, None, 4, None]

        dll.ldap_get_valuesW.side_effect = [['1.1'], ['1.2', '1.3'], [], ['4']]

        ret = []
        res = [mock.Mock(), None]
        res[0].contents.bv_len = 3
        res[0].contents.bv_val = create_string_buffer(b'1.1___')
        ret.append(res)

        res = [mock.Mock(), mock.Mock(), None]
        res[0].contents.bv_len = 3
        res[0].contents.bv_val = create_string_buffer(b'1.2___')
        res[1].contents.bv_len = 3
        res[1].contents.bv_val = create_string_buffer(b'1.3___')
        ret.append(res)

        ret.append(None)

        res = [mock.Mock(), None]
        res[0].contents.bv_len = 1
        res[0].contents.bv_val = create_string_buffer(b'4___')
        ret.append(res)

        dll.ldap_get_values_lenW.side_effect = ret

        expects = [{1: [b'1.1'], 2: [b'1.2', b'1.3']}, {3: [], 4: [b'4']}]

        mock_l = mock.Mock()
        mock_m = mock.Mock()
        message = Message(mock_l, mock_m)
        self.assertEqual(parse_binary_message(message), expects)

    def test_parse_message_empty(self, dll):
        dll.ldap_first_entry.return_value = None

        mock_l = mock.Mock()
        mock_m = mock.Mock()
        message = Message(mock_l, mock_m)
        self.assertEqual(parse_message(message), [])
