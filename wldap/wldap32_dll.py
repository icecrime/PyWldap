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

from ctypes import POINTER, cdll, c_int, c_void_p, c_ulong, c_wchar_p


# Extract from Winldap.h:
#
#    If you have UNICODE defined at compile time, you'll pull in the unicode
#    versions of the calls.  Note that your executable may then not work with
#    other implementations of the LDAP API that don't support Unicode.  If
#    UNICODE is not defined, then we define the LDAP calls without the trailing
#    'A' (as in ldap_bind rather than ldap_bindA) so that your app may work
#    with other implementations that don't support Unicode.
#
#    The import library has all three forms of the call present... ldap_bindW,
#    ldap_bindA, and ldap_bind.  ldap_bindA simply calls ldap_bind.  ldap_bind
#    simply converts the arguments to unicode and calls ldap_bindW.  The
#    reason this is done is because we have to put UTF-8 on the wire, so if
#    we converted from Unicode to single byte, we'd loose information.  Since
#    all core processing is done in Unicode, nothing is lost.
#
# In Python 2, it is simply to much pain to support both str an unicode in the
# same module, so we just take a radical decision and go for full unicode.

dll = cdll.Wldap32

exposed_functions = [

    # void ber_free(
    #   __in  BerElement *pBerElement,
    #   __in  INT fbuf
    # );
    [
        'ber_free',
        'ber_free',
        None,
        [c_void_p, c_int]
    ],

    # ULONG ldap_abandon(
    #   __in   LDAP *ld,
    #   __out  ULONG msgid
    # );
    [
        'ldap_abandon',
        'ldap_abandon',
        c_ulong,
        [c_void_p, c_ulong]
    ],

    # ULONG ldap_bind_s(
    #   __in  LDAP *ld,
    #   __in  PCHAR dn,
    #   __in  PCHAR cred,
    #   __in  ULONG method
    # );
    [
        'ldap_bind_s',
        'ldap_bind_sW',
        c_ulong,
        [c_void_p, c_wchar_p, c_wchar_p, c_ulong]
    ],

    # ULONG ldap_bind(
    #   __in  LDAP *ld,
    #   __in  PCHAR dn,
    #   __in  PCHAR cred,
    #   __in  ULONG method
    # );
    [
        'ldap_bind',
        'ldap_bindW',
        c_ulong,
        [c_void_p, c_wchar_p, c_wchar_p, c_ulong]
    ],

    # ULONG LDAPAPI ldap_cleanup(
    #   HANDLE  hInstance
    # );
    [
        'ldap_cleanup',
        'ldap_cleanup',
        c_ulong,
        [c_void_p]
    ],

    # PCHAR ldap_first_attribute(
    #   __in   LDAP *ld,
    #   __in   LDAPMessage *entry,
    #   __out  BerElement **ptr
    # );
    [
        'ldap_first_attribute', 'ldap_first_attributeW',
        c_wchar_p,
        [c_void_p, c_void_p, POINTER(c_void_p)]
    ],

    # LDAPMessage* ldap_first_entry(
    #   __in  LDAP *ld,
    #   __in  LDAPMessage *res
    # );
    [
        'ldap_first_entry',
        'ldap_first_entry',
        c_void_p,
        [c_void_p, c_void_p]
    ],

    # PCHAR* ldap_get_values(
    #   __in  LDAP *ld,
    #   __in  LDAPMessage *entry,
    #   __in  PCHAR attr
    # );
    [
        'ldap_get_values',
        'ldap_get_valuesW',
        POINTER(c_wchar_p),
        [c_void_p, c_void_p, c_wchar_p]
    ],
    
    # ULONG ldap_get_option(
    #   __in   LDAP *ld,
    #   __in   int option,
    #   __out  void *outvalue
    # );
    [
        'ldap_get_option',
        'ldap_get_option',
        c_ulong,
        [c_void_p, c_int, c_void_p]
    ],

    # LDAP* ldap_init(
    #   __in  PCHAR HostName,
    #   __in  ULONG PortNumber
    # );
    [
        'ldap_init',
        'ldap_initW',
        c_void_p,
        [c_wchar_p, c_ulong]
    ],

    # VOID ldap_memfree(
    #   __in  PCHAR Block
    # );
    [
        'ldap_memfree',
        'ldap_memfreeW',
        None,
        [c_wchar_p]
    ],

    # ULONG ldap_msgfree(
    #   __in  LDAPMessage *res
    # );
    [
        'ldap_msgfree',
        'ldap_msgfree',
        c_ulong,
        [c_void_p]
    ],

    # PCHAR ldap_next_attribute(
    #   __in     LDAP *ld,
    #   __in     LDAPMessage *entry,
    #   __inout  BerElement *ptr
    # );
    [
        'ldap_next_attribute',
        'ldap_next_attributeW',
        c_wchar_p,
        [c_void_p, c_void_p, c_void_p]
    ],

    # LDAPMessage* ldap_next_entry(
    #   __in  LDAP *ld,
    #   __in  LDAPMessage *entry
    # );
    [
        'ldap_next_entry',
        'ldap_next_entry',
        c_void_p,
        [c_void_p, c_void_p]
    ],

    # ULONG ldap_result(
    #   __in   LDAP *ld,
    #   __in   ULONG msgid,
    #   __in   ULONG all,
    #   __in   struct l_timeval *timeout,
    #   __out  LDAPMessage **res
    # );
    [
        'ldap_result',
        'ldap_result',
        c_ulong,
        [c_void_p, c_ulong, c_ulong, c_void_p, POINTER(c_void_p)]
    ],

    # ULONG ldap_search_s(
    #   __in   LDAP *ld,
    #   __in   PCHAR base,
    #   __in   ULONG scope,
    #   __in   PCHAR filter,
    #   __in   PCHAR attrs[],
    #   __in   ULONG attrsonly,
    #   __out  LDAPMessage **res
    # );
    [
        'ldap_search_s',
        'ldap_search_sW',
        c_ulong,
        [c_void_p, c_wchar_p, c_ulong, c_wchar_p, POINTER(c_wchar_p), c_ulong,
         POINTER(c_void_p)]
    ],

    # ULONG ldap_search(
    #   _In_  LDAP *ld,
    #   _In_  PCHAR base,
    #   _In_  ULONG scope,
    #   _In_  PCHAR filter,
    #   _In_  PCHAR attrs[],
    #   _In_  ULONG attrsonly
    # );
    [
        'ldap_search',
        'ldap_searchW',
        c_ulong,
        [c_void_p, c_wchar_p, c_ulong, c_wchar_p, POINTER(c_wchar_p), c_ulong]
    ],

    # ULONG ldap_set_option(
    #   __in  LDAP *ld,
    #   __in  int option,
    #   __in  void *invalue
    # );
    [
        'ldap_set_option',
        'ldap_set_optionW',
        c_ulong,
        [c_void_p, c_int, c_void_p]
    ],

    # ULONG ldap_simple_bind_s(
    #   __in  LDAP *ld,
    #   __in  PCHAR dn,
    #   __in  PCHAR passwd
    # );
    [
        'ldap_simple_bind_s',
        'ldap_simple_bind_sW',
        c_ulong,
        [c_void_p, c_wchar_p, c_wchar_p]
    ],

    # ULONG ldap_simple_bind(
    #   __in  LDAP *ld,
    #   __in  PCHAR dn,
    #   __in  PCHAR passwd
    # );
    [
        'ldap_simple_bind',
        'ldap_simple_bindW',
        c_ulong,
        [c_void_p, c_wchar_p, c_wchar_p]
    ],

    # ULONG ldap_unbind_s(
    #   __in  LDAP *ld
    # );
    [
        'ldap_unbind_s',
        'ldap_unbind_s',
        c_ulong,
        [c_void_p]
    ],

    # ULONG ldap_unbind[
    #   __in  LDAP *ld
    # ];
    [
        'ldap_unbind',
        'ldap_unbind',
        c_ulong,
        [c_void_p]
    ],

    # ULONG ldap_value_free(
    #   PCHAR *vals
    # );
    [
        'ldap_value_free',
        'ldap_value_freeW',
        c_ulong,
        [POINTER(c_wchar_p)]
    ],
]


def initialize():
    from collections import namedtuple
    FunctionTemplate = namedtuple(
        'FunctionTemplate',
        ['exported_name', 'api_name', 'restype', 'argtypes']
    )

    for exposed_function in exposed_functions:
        fn_data = FunctionTemplate(*exposed_function)

        # Retrieve Wldap32.dll exposed function and register its signature for
        # the ctypes module.
        fn_ldap = getattr(dll, fn_data.api_name)
        fn_ldap.restype = fn_data.restype
        fn_ldap.argtypes = fn_data.argtypes

        # Define a new module level function which forwards to the underlying
        # call. We go through getattr rather than directly referencing fn_data
        # in the function body to allow mocking the dll object in the tests.
        def _api_caller(fn_data=fn_data):
            def _wrapped(*args, **kwargs):
                return getattr(dll, fn_data.api_name)(*args, **kwargs)
            return _wrapped
        globals()[fn_data.exported_name] = _api_caller()


initialize()
del initialize
