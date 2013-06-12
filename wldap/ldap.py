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

from wldap import wldap32_dll as dll
from wldap.changeset import Changeset
from wldap.message import Message
from wldap.wldap32_constants import LDAP_PORT
from wldap.wldap32_structures import LDAP_TIMEVAL


class ldap(object):
    """Root object representing Windows' Wldap LDAP instance."""

    def __init__(self, hostName=None, portNumber=LDAP_PORT):
        """Construct a new ldap instance.

        Args:
            hostName: host string ("default" LDAP server if NULL)
            portNumber: TCP port to which to connect
        """
        self._l = dll.ldap_init(hostName, portNumber)

    def abandon(self, msgid):
        return dll.ldap_abandon(self._l, msgid)

    def add_s(self, dn, *args):
        """Initiate an synchronous add operation to a directory tree.

        Args:
            dn: distinguished name for the entry to add
            *args: (attribute, values) pairs, where values is itself a sequence
        """
        changeset = Changeset()
        [changeset.add(dn, attr, values) for attr, values in args]
        return dll.ldap_add(self._l, dn, changeset.to_api_param())

    def add(self, dn, *args):
        """Initiate an asynchronous add operation to a directory tree.

        Args:
            dn: distinguished name for the entry to add
            *args: (attribute, values) pairs, where value is a sequence
        """
        changeset = Changeset()
        [changeset.add(dn, attr, values) for attr, values in args]
        return dll.ldap_add(self._l, dn, changeset.to_api_param())

    def bind_s(self, dn, cred, method):
        return dll.ldap_bind_s(self._l, dn, cred, method)

    def bind(self, dn, cred, method):
        return dll.ldap_bind(self._l, dn, cred, method)

    def check_filter(self, search_filter):
        return dll.ldap_check_filter(self._l, search_filter)

    def connect(self, timeout_seconds=None):
        timeval = None
        if timeout_seconds:
            timeval = LDAP_TIMEVAL.from_fractional_seconds(timeout_seconds)
        return dll.ldap_connect(self._l, timeval and byref(timeval))

    def delete_s(self, dn):
        """Initiate a synchronous delete operation from the directory tree.

        Args:
            dn: distinguished name for the entry to delete
        """
        return dll.ldap_delete_s(self._l, dn)

    def delete(self, dn):
        """Initiate a asynchronous delete operation from the directory tree.

        Args:
            dn: distinguished name for the entry to delete
        """
        return dll.ldap_delete(self._l, dn)

    def modify_s(self, dn, changeset):
        """Initiate an synchronous modify operation to the directory tree.

        Args:
            dn: distinguished name for the entry to delete
            changeset: a wldap.Changeset containing the requested modifications
        """
        return dll.ldap_modify(self._l, dn, changeset.to_api_param())

    def modify(self, dn, changeset):
        """Initiate an asynchronous modify operation to the directory tree.

        Args:
            dn: distinguished name for the entry to delete
            changeset: a wldap.Changeset containing the requested modifications
        """
        return dll.ldap_modify(self._l, dn, changeset.to_api_param())

    def _search(self, fn, base, scope, filt, attr, attronly):
        result = c_void_p()

        # Convert attribute list to a C, nul-terminated string array.
        attr = attr + [None]
        attr = (c_wchar_p * len(attr))(*attr)

        # Last parameter is a LDAPMessage**, thus the need for a byref().
        fn(self._l, base, scope, filt, attr, attronly, byref(result))
        return Message(self._l, result)

    def search_s(self, base, scope, filt, attr, attronly):
        fn = dll.ldap_search_s
        return self._search(fn, base, scope, filt, attr, attronly)

    def search(self, base, scope, filt, attr, attronly):
        fn = dll.ldap_search
        return self._search(fn, base, scope, filt, attr, attronly)

    def simple_bind_s(self, dn, passwd):
        return dll.ldap_simple_bind_s(self._l, dn, passwd)

    def simple_bind(self, dn, passwd):
        return dll.ldap_simple_bind(self._l, dn, passwd)

    def unbind_s(self):
        return dll.ldap_unbind_s(self._l)

    def unbind(self):
        return dll.ldap_unbind(self._l)
