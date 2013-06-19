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

from ctypes import byref, c_wchar_p

from wldap import wldap32_dll as dll
from wldap.changeset import Changeset
from wldap.exceptions import LdapError
from wldap.future import Future
from wldap.message import Message
from wldap.wldap32_constants import LDAP_PORT, LDAP_SUCCESS
from wldap.wldap32_structures import LDAP_TIMEVAL, LDAPMessage


class ldap(object):
    """Root object representing Windows' Wldap LDAP instance."""

    def __init__(self, hostName=None, portNumber=LDAP_PORT):
        """Construct a new ldap instance.

        Args:
            hostName: host string ("default" LDAP server if NULL)
            portNumber: TCP port to which to connect
        """
        self._l = dll.ldap_init(hostName, portNumber)
        self._unbound = False

    def __del__(self):
        try:
            if not self._unbound:
                self.unbind()
        except LdapError:  # pragma: no cover
            # I'm a C++ developed, my religion forbids me throwing from a dtor
            pass

    @staticmethod
    def _make_attrs(attrs):
        # Convert attribute list to a C, nul-terminated string array.
        c_attr = attrs + [None]
        c_attr = (c_wchar_p * len(c_attr))(*c_attr)
        return c_attr

    @staticmethod
    def _make_timeval(timeout_seconds):
        """Converts a timeout expressed in fractional seconds to a LDAP_TIMEVAL
        structure suitable to pass to Wldap32.
        """
        timeval = None
        if timeout_seconds is not None:
            timeval = LDAP_TIMEVAL.from_fractional_seconds(timeout_seconds)
        return timeval

    def abandon(self, msgid):
        """Cancel an in-process asynchronous LDAP call.

        Return a boolean indicating if the cancel operation is successful.
        """
        return dll.ldap_abandon(self._l, msgid) == LDAP_SUCCESS

    def add_s(self, dn, *args):
        """Initiate a synchronous add operation to a directory tree.

        Args:
            dn: distinguished name for the entry to add
            *args: (attribute, values) pairs, where values is itself a sequence

        Returns nothing, and raises LdapError on error.
        """
        changeset = Changeset()
        [changeset.add(attr, values) for attr, values in args]
        dll.ldap_add_s(self._l, dn, changeset.to_api_param())

    def add(self, dn, *args):
        """Initiate an asynchronous add operation to a directory tree.

        Args:
            dn: distinguished name for the entry to add
            *args: (attribute, values) pairs, where value is a sequence

        Returns a Future object, and raises LdapError on error.
        """
        changeset = Changeset()
        [changeset.add(attr, values) for attr, values in args]
        return Future(self, dll.ldap_add(self._l, dn,
                                         changeset.to_api_param()))

    def bind_s(self, dn, cred, method):
        """Initiate a synchronous operation to authenticate the client to the
        LDAP server.

        Args:
            dn: distinguished name of the entry used to bind
            cred: credentials with which to authenticate
            method: authenticatation method to use

        Acceptable method values:

            LDAP_AUTH_SIMPLE
            LDAP_AUTH_DIGEST
            LDAP_AUTH_DPA
            LDAP_AUTH_MSN
            LDAP_AUTH_NEGOTIATE
            LDAP_AUTH_NTLM
            LDAP_AUTH_SICILY
            LDAP_AUTH_SSPI

        Returns nothing, and raises LdapError on error.

        See http://msdn.microsoft.com/en-us/library/windows/desktop/aa366156(v=
        vs.85).aspx for details.
        """
        dll.ldap_bind_s(self._l, dn, cred, method)

    def bind(self, dn, cred, method):
        """Initiate an asynchronous operation to authenticate the client to the
        LDAP server.

        Args:
            dn: distinguished name of the entry used to bind
            cred: credentials with which to authenticate
            method: authenticatation method to use

        LDAP_AUTH_SIMPLE is the only acceptable method for the asynchronous
        version of bind(), and credentials are sent in plaintext. In the end,
        you're better off using bind_s.

        Returns a Future object, and raises LdapError on error.

        See http://msdn.microsoft.com/en-us/library/windows/desktop/aa366153(v=
        vs.85).aspx for details.
        """
        return Future(self, dll.ldap_bind(self._l, dn, cred, method))

    def check_filter(self, search_filter):
        """Verify `search_filter` syntax.

        Returns True or an LdapError.
        """
        try:
            ret = dll.ldap_check_filter(self._l, search_filter) == LDAP_SUCCESS
        except LdapError as e:
            ret = e
        return ret  # TODO Either True or LdapError(): is that weird?

    def connect(self, timeout_seconds=None):
        """Establish a connection with the server.

        Returns nothing, and raises LdapError on error.
        """
        timeval = self._make_timeval(timeout_seconds)
        dll.ldap_connect(self._l, timeval and byref(timeval))

    def delete_s(self, dn):
        """Initiate a synchronous delete operation from the directory tree.

        Args:
            dn: distinguished name for the entry to delete

        Returns nothing, and raises LdapError on error.
        """
        dll.ldap_delete_s(self._l, dn)

    def delete(self, dn):
        """Initiate a asynchronous delete operation from the directory tree.

        Args:
            dn: distinguished name for the entry to delete

        Returns a Future object, and raises LdapError on error.
        """
        return Future(self, dll.ldap_delete(self._l, dn))

    def modify_s(self, dn, changeset):
        """Initiate a synchronous modify operation to the directory tree.

        Args:
            dn: distinguished name for the entry to delete
            changeset: a wldap.Changeset containing the requested modifications

        Returns nothing, and raises LdapError on error.
        """
        dll.ldap_modify_s(self._l, dn, changeset.to_api_param())

    def modify(self, dn, changeset):
        """Initiate an asynchronous modify operation to the directory tree.

        Args:
            dn: distinguished name for the entry to delete
            changeset: a wldap.Changeset containing the requested modifications

        Returns a Future object, and raises LdapError on error.
        """
        return Future(self, dll.ldap_modify(self._l, dn,
                                            changeset.to_api_param()))

    def result(self, msgid, all_, timeout_seconds=None):
        """Obtain the result of an asynchronous operation.

        Args:
            msgid: the message ID of the operation
            all_: specifies how many messages are received in a single call
            timeout_seconds: a fractional number of seconds to wait for the
                result, block indefinitely if None (default)

        Returns a Message object, or None on timeout.
        """
        res = LDAPMessage.pointer()
        timeval = self._make_timeval(timeout_seconds)
        ret = dll.ldap_result(self._l, msgid, all_, timeval and byref(timeval),
                              byref(res))
        return Message(self._l, res) if ret != 0 else None  # 0 is a timeout

    def search_s(self, base, scope, filt, attr, attronly):
        """Initiate a synchronous search operation.

        Args:
            base: distinguished name of the entry at which to start the search
            scope: LDAP_SCOPE_BASE, LDAP_SCOPE_ONELEVEL or LDAP_SCOPE_SUBTREE
            filt: the search filter
            attr: a list of attribute names to be returned
            attronly: True if both attribute types and values are to be
                returned, False if only types are required

        Returns a Message object, and raises LdapError on error.
        """
        # Last parameter is a LDAPMessage**, thus the need for a byref(). The
        # return value is not verified as the module raises on error.
        res = LDAPMessage.pointer()
        attr = self._make_attrs(attr)
        dll.ldap_search_s(self._l, base, scope, filt, attr, attronly,
                          byref(res))
        return Message(self._l, res)

    def search(self, base, scope, filt, attr, attronly):
        """Initiate an asynchronous search operation.

        Args:
            base: distinguished name of the entry at which to start the search
            scope: LDAP_SCOPE_BASE, LDAP_SCOPE_ONELEVEL or LDAP_SCOPE_SUBTREE
            filt: the search filter
            attr: a list of attribute names to be returned
            attronly: True if both attribute types and values are to be
                returned, False if only types are required

        Returns a Future object, and raises LdapError on error.
        """
        # Convert attribute list to a C, nul-terminated string array.
        attr = self._make_attrs(attr)
        return Future(self, dll.ldap_search(self._l, base, scope, filt, attr,
                                            attronly))

    def simple_bind_s(self, dn, passwd):
        """Initiate a synchronous request to authenticate with the server using
        a plaintext password.

        Returns nothing, and raises LdapError on error.
        """
        dll.ldap_simple_bind_s(self._l, dn, passwd)

    def simple_bind(self, dn, passwd):
        """Initiate an asynchronous request to authenticate with the server
        using a plaintext password.

        Returns a Future object, and raises LdapError on error.
        """
        return Future(self, dll.ldap_simple_bind(self._l, dn, passwd))

    def unbind_s(self):
        """Synchronously free resources associated with the LDAP session. There
        is no functional difference between unbind() and unbind_s().

        Returns nothing, and raises LdapError on error.
        """
        if not self._unbound:
            dll.ldap_unbind_s(self._l)
            self._unbound = True

    def unbind(self):
        """Synchronously free resources associated with the LDAP session. There
        is no functional difference between unbind() and unbind_s().

        Returns nothing, and raises LdapError on error.
        """
        if not self._unbound:
            dll.ldap_unbind(self._l)
            self._unbound = True
