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

from ctypes import byref, string_at
from itertools import takewhile

from wldap import wldap32_dll as dll
from wldap.wldap32_structures import BerElement


class MessageAttribute(object):
    """MessageAttribute: kind of (attribute, [values])."""

    def __init__(self, ldap, message, name):
        """Construct a new MessageAttribute instance.

        Args:
            ldap: low level LDAP* pointer
            message: the Message instance which attribute we want to extract
            name: the attribute string identifier
        """
        self.name = name
        self._ldap = ldap
        self._message = message

    @property
    def binary_values(self):
        # Cf. MSDN: ldap_get_values_len should be used instead of
        # ldap_get_values for binary data. The function may return NULL when no
        # attributes values were found.
        val = dll.ldap_get_values_len(self._ldap, self._message, self.name)
        if val is None:
            return

        try:
            idx = 0
            while val[idx]:
                yield string_at(val[idx].contents.bv_val,
                                val[idx].contents.bv_len)
                idx = idx + 1
        finally:
            dll.ldap_value_free_len(val)

    @property
    def values(self):
        # Cf. MSDN ldap_get_values documentation: 'Call ldap_value_free to
        # release the returned value when it is no longer required'.
        val = dll.ldap_get_values(self._ldap, self._message, self.name)
        if val is None:
            return

        try:
            for item in takewhile(bool, val):
                yield item
        finally:
            dll.ldap_value_free(val)


class MessageEntryIterator(object):
    """Implements iteration over LDAPMessage* attributes."""

    def __init__(self, ldap, message):
        """Construct a new MessageEntryIterator instance.

        Args:
            ldap: low level LDAP* pointer
            message: the Message instance which attributes we want to extract
        """
        self._ldap = ldap
        self._message = message
        self._berElem = BerElement.pointer()
        self._attribute = dll.ldap_first_attribute(self._ldap, self._message,
                                                   byref(self._berElem))

    def __del__(self):
        # Cf MSDN ldap_first_attribute documentation: 'When you have finished
        # stepping through a list of attributes and ptr is non-NULL, free the
        # pointer by calling ber_free( ptr, 0 ). Be aware that you must pass
        # the second parameter as 0 (zero) in this call.
        if hasattr(self, '_berElem') and self._berElem:  # pragma: no cover
            dll.ber_free(self._berElem, 0)

    def __next__(self):  # pragma: no cover
        return self.next()

    def next(self):
        # Because of the first / next API asymmetry, we're always 'off by one',
        # so the previously fetched value is tested before moving on.
        if self._attribute is None:
            raise StopIteration

        # Wrap the previously fetched value in a MessageAttribute object before
        # going with the iteration.
        current = MessageAttribute(self._ldap, self._message, self._attribute)
        self._attribute = dll.ldap_next_attribute(self._ldap, self._message,
                                                  self._berElem)
        return current


class MessageEntry(object):
    """MessageEntry."""

    def __init__(self, ldap, message_entry):
        """Construct a new MessageEntry instance.

        Args:
            ldap: low level LDAP* pointer
            entry: a LDAPMessage* as obtained through ldap_(first|next)_entry
        """
        self._l = ldap
        self._message_entry = message_entry

    def __getitem__(self, attributeName):
        return MessageAttribute(self._l, self._message_entry, attributeName)

    def __iter__(self):
        return MessageEntryIterator(self._l, self._message_entry)

    def __len__(self):
        return dll.ldap_count_entries(self._l, self._message_entry)


class MessageIterator(object):
    """Implements iteration over LDAPMessage* entries."""

    def __init__(self, ldap, message):
        """Construct a new MessageIterator instance.

        Args:
            ldap: low level LDAP* pointer
            message: a LDAPMessage* as obtained, for example, through search
        """
        self._ldap = ldap
        self._current = dll.ldap_first_entry(self._ldap, message)

    def __next__(self):  # pragma: no cover
        return self.next()

    def next(self):
        # Because of the first / next API asymmetry, we're always 'off by one',
        # so the previously fetched value is tested before moving on.
        if not self._current:
            raise StopIteration

        # Wrap the previously fetched value in a MessageEntry object before
        # going with the iteration.
        current = MessageEntry(self._ldap, self._current)
        self._current = dll.ldap_next_entry(self._ldap, self._current)
        return current


class Message(object):
    """Wrapper over Wldap LDAPMessage.

    Message is an iterable sequence of MessageEntry.
    """

    def __init__(self, ldap, message):
        """Construct a new Message instance.

        Args:
            ldap: low level LDAP* pointer
            message: a LDAPMessage* as obtained, for example, through search
        """
        self._ldap = ldap
        self._message = message

    def __del__(self):
        # This is essentially the reason of this object existence: ensure
        # proper releasing of the underlying resources.
        if hasattr(self, '_message'):
            dll.ldap_msgfree(self._message)

    def __iter__(self):
        return MessageIterator(self._ldap, self._message)

    def __len__(self):
        return dll.ldap_count_entries(self._ldap, self._message)


def parse_message(msg):
    """Builds a list of dictionaries for the provided Message instance by
    iterating over every attribute of every message entry. Attribute values are
    returned as unicode strings.

    Args:
        message: a Message instance as obtained, for example, by searching
    """
    return [{a.name: list(a.values) for a in entry} for entry in msg]


def parse_binary_message(msg):
    """Builds a list of dictionaries for the provided Message instance by
    iterating over every attribute of every message entry. Attribute values are
    returned as bytes (str object in Python 2.x, bytes object in 3.x).

    Args:
        message: a Message instance as obtained, for example, by searching
    """
    return [{a.name: list(a.binary_values) for a in entry} for entry in msg]
