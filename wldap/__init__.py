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

from ctypes import byref, c_void_p, c_wchar_p
from itertools import takewhile

from . import wldap32_dll as dll


###############################################################################

class MessageAttribute(object):
    """MessageAttribute: kind of (attribute, [values])."""

    def __init__(self, ldap, message, attrib):
        """Construct a new MessageAttribute instance.

        Args:
            ldap: low level LDAP* pointer
            message: the Message instance which attribute we want to extract
            attrib: the attribute string identifier
        """
        self.name = attrib
        self.raw_values = dll.ldap_get_values(ldap, message, attrib)

    def __del__(self):
        # Cf. MSDN ldap_get_values documentation: 'Call ldap_value_free to
        # release the returned value when it is no longer required'.
        if hasattr(self, 'raw_values'):
            dll.ldap_value_free(self.raw_values)

    def __str__(self):
        return str((self.name, self.values))

    @property
    def values(self):
        return takewhile(bool, self.raw_values)


###############################################################################


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
        self._berElem = c_void_p()
        self._attribute = dll.ldap_first_attribute(self._ldap, self._message,
                                                   byref(self._berElem))

    def __del__(self):
        # Cf MSDN ldap_first_attribute documentation: 'When you have finished
        # stepping through a list of attributes and ptr is non-NULL, free the
        # pointer by calling ber_free( ptr, 0 ). Be aware that you must pass
        # the second parameter as 0 (zero) in this call.
        if hasattr(self, '_berElem') and self._berElem:
            dll.ber_free(self._berElem, 0)

    def next(self):
        # Because of the first / next API asymmetry, we're always 'off by one',
        # so the previously fetched value is tested before moving on.
        if not self._attribute:
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

    def __iter__(self):
        return MessageEntryIterator(self._l, self._message_entry)

    def __getitem__(self, attributeName):
        return MessageAttribute(self._l, self._message_entry, attributeName)


###############################################################################


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


###############################################################################


class ldap(object):
    """Root object representing Windows' Wldap LDAP instance."""

    def __init__(self, hostName=None, portNumber=dll.LDAP_PORT):
        """Construct a new ldap instance.

        Args:
            hostName: host string ("default" LDAP server if NULL)
            portNumber: TCP port to which to connect
        """
        self._l = dll.ldap_init(hostName, portNumber)

    def abandon(self, msgid):
        return dll.ldap_abandon(self._l, msgid)

    def bind(self, dn, cred, method):
        return dll.ldap_bind(self._l, dn, cred, method)

    def bind_s(self, dn, cred, method):
        return dll.ldap_bind_s(self._l, dn, cred, method)

    def _search(self, fn, base, scope, filt, attr, attronly):
        result = c_void_p()

        # Convert attribute list to a C, nul-terminated string array.
        attr = attr + [None]
        attr = (c_wchar_p * len(attr))(*attr)

        # Last parameter is a LDAPMessage**, thus the need for a byref().
        ret = fn(self._l, base, scope, filt, attr, attronly, byref(result))
        return not ret and Message(self._l, result) or None

    def search(self, base, scope, filt, attr, attronly):
        fn = dll.ldap_search
        return self._search(fn, base, scope, filt, attr, attronly)

    def search_s(self, base, scope, filt, attr, attronly):
        fn = dll.ldap_search_s
        return self._search(fn, base, scope, filt, attr, attronly)

    def simple_bind(self, dn, passwd):
        return dll.ldap_simple_bind(self._l, dn, passwd)

    def simple_bind_s(self, dn, passwd):
        return dll.ldap_simple_bind_s(self._l, dn, passwd)

    def unbind(self):
        return dll.ldap_unbind(self._l)

    def unbind_s(self):
        return dll.ldap_unbind_s(self._l)


def parse_message(message):
    """Builds a dictionary for the provided Message instance by iterating over
    every attribute of every entry.

    Args:
        message: a Message instance as returned, for example, by searching
    """
    output = {}
    for entry in message:
        output.update({a.name: list(a.values) for a in entry})
    return output
