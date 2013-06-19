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

from wldap.exceptions import LdapError
from wldap.wldap32_constants import ReturnCodes
from wldap.wldap32_structures import BerElement, LDAP_BERVAL, LDAP_TIMEVAL
from wldap.wldap32_structures import LDAP, LDAPMessage, LDAPMod


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


def errcheck_compare(result, func, arguments):
    """Error checking strategy for compare functions, which return either
    LDAP_COMPARE_TRUE, LDAP_COMPARE_FALSE, or an error code.

    Raise an LdapError if the returned value is neither LDAP_COMPARE_TRUE or
    LDAP_COMPARE_FALSE.
    """
    if result == ReturnCodes.LDAP_COMPARE_TRUE:
        return True
    if result == ReturnCodes.LDAP_COMPARE_FALSE:
        return False
    raise LdapError(error_code=result)


def errcheck_pointer(result, func, arguments):
    """Error checking strategy for functions returning a pointer.

    Raise an LdapError if the returned pointer is NULL and LdapGetLastError()
    is not LDAP_SUCCESS (the `ldap_next_*` family returns NULL pointer when the
    iterator is exhausted, and it shouldn't raise an LdapError).
    """
    if not result:  # c_void_p has __nonzero__
        code = LdapGetLastError()
        if code != ReturnCodes.LDAP_SUCCESS:
            raise LdapError(code)
    return result


def errcheck_retcode(result, func, arguments):
    """Error checking strategy for functions returning an error code. This
    family of functions include synchronous calls such as ldap_bind_s.

    Raise an LdapError if the returned code is different from 0.
    """
    if result != ReturnCodes.LDAP_SUCCESS:
        raise LdapError(error_code=result)
    return result


def errcheck_sentinel(result, func, arguments):
    """Error checking strategy for functions returning a sentinel value. This
    family of functions include asynchronous calls such as ldap_bind.
    """
    if result == -1:
        raise LdapError()
    return result


# The exposed_functions sequence describes the API calls we want to export and
# route. The 'structure' is:
#
#   [
#       'module_function_name',
#       'underlying_function_name',
#       return_type,
#       [arg1_type, arg2_type, ...],
#       error_checking_function
#   ]

exposed_functions = [

    # void ber_free(
    #   __in  BerElement *pBerElement,
    #   __in  INT fbuf
    # );
    [
        'ber_free',
        'ber_free',
        None,
        [BerElement.pointer, c_int],
        None
    ],

    # ULONG ldap_add_s(
    #   _In_  LDAP *ld,
    #   _In_  PCHAR dn,
    #   _In_  LDAPMod *attrs[]
    # );
    [
        'ldap_add_s',
        'ldap_add_sW',
        c_ulong,
        [LDAP.pointer, c_wchar_p, POINTER(LDAPMod.pointer)],
        errcheck_retcode
    ],

    # ULONG ldap_add(
    #   _In_  LDAP *ld,
    #   _In_  PCHAR dn,
    #   _In_  LDAPMod *attrs[]
    # );
    [
        'ldap_add',
        'ldap_addW',
        c_ulong,
        [LDAP.pointer, c_wchar_p, POINTER(LDAPMod.pointer)],
        errcheck_sentinel
    ],

    # ULONG ldap_abandon(
    #   __in   LDAP *ld,
    #   __out  ULONG msgid
    # );
    [
        'ldap_abandon',
        'ldap_abandon',
        c_ulong,
        [LDAP.pointer, c_ulong],
        None  # No server response from ldap_abandon
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
        [LDAP.pointer, c_wchar_p, c_wchar_p, c_ulong],
        errcheck_retcode
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
        [LDAP.pointer, c_wchar_p, c_wchar_p, c_ulong],
        errcheck_sentinel
    ],

    # ULONG ldap_check_filter(
    #   _In_  LDAP *ld,
    #   _In_  PWCHAR SearchFilter
    # );
    [
        'ldap_check_filter',
        'ldap_check_filterW',
        c_ulong,
        [LDAP.pointer, c_wchar_p],
        errcheck_retcode
    ],

    # ULONG LDAPAPI ldap_cleanup(
    #   HANDLE  hInstance
    # );
    [
        'ldap_cleanup',
        'ldap_cleanup',
        c_ulong,
        [c_void_p],
        errcheck_retcode
    ],

    # ULONG ldap_compare_s(
    #   _In_  LDAP *ld,
    #   _In_  PCHAR dn,
    #   _In_  PCHAR attr,
    #   _In_  PCHAR value
    # );
    [
        'ldap_compare_s',
        'ldap_compare_sW',
        c_ulong,
        [LDAP.pointer, c_wchar_p, c_wchar_p, c_wchar_p],
        errcheck_compare
    ],

    # ULONG ldap_compare(
    #   _In_  LDAP *ld,
    #   _In_  PCHAR dn,
    #   _In_  PCHAR attr,
    #   _In_  PCHAR value
    # );
    [
        'ldap_compare',
        'ldap_compareW',
        c_ulong,
        [LDAP.pointer, c_wchar_p, c_wchar_p, c_wchar_p],
        errcheck_sentinel
    ],

    # ULONG ldap_connect(
    #   _In_  LDAP *ld,
    #   _In_  LDAP_TIMEVAL *timeout
    # );
    [
        'ldap_connect',
        'ldap_connect',
        c_ulong,
        [LDAP.pointer, LDAP_TIMEVAL.pointer],
        errcheck_retcode
    ],

    # ULONG ldap_count_entries(
    #   _In_  LDAP *ld,
    #   _In_  LDAPMessage *res
    # );
    [
        'ldap_count_entries',
        'ldap_count_entries',
        c_ulong,
        [LDAP.pointer, LDAPMessage.pointer],
        errcheck_sentinel
    ],

    # PCHAR ldap_first_attribute(
    #   __in   LDAP *ld,
    #   __in   LDAPMessage *entry,
    #   __out  BerElement **ptr
    # );
    [
        'ldap_first_attribute',
        'ldap_first_attributeW',
        c_wchar_p,
        [LDAP.pointer, LDAPMessage.pointer, POINTER(BerElement.pointer)],
        errcheck_pointer
    ],

    # ULONG ldap_delete_s(
    #   _In_  LDAP *ld,
    #   _In_  PCHAR dn
    # );
    [
        'ldap_delete_s',
        'ldap_delete_sW',
        c_ulong,
        [LDAP.pointer, c_wchar_p],
        errcheck_retcode
    ],

    # ULONG ldap_delete(
    #   _In_  LDAP *ld,
    #   _In_  PCHAR dn
    # );
    [
        'ldap_delete',
        'ldap_deleteW',
        c_ulong,
        [LDAP.pointer, c_wchar_p],
        errcheck_sentinel
    ],

    # PCHAR ldap_err2string(
    #   _In_  ULONG err
    # );
    [
        'ldap_err2string',
        'ldap_err2stringW',
        c_wchar_p,
        [c_ulong],
        None  # Returns null on failure
    ],

    # LDAPMessage* ldap_first_entry(
    #   __in  LDAP *ld,
    #   __in  LDAPMessage *res
    # );
    [
        'ldap_first_entry',
        'ldap_first_entry',
        LDAPMessage.pointer,
        [LDAP.pointer, LDAPMessage.pointer],
        errcheck_pointer
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
        [LDAP.pointer, c_int, c_void_p],
        errcheck_retcode
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
        [LDAP.pointer, LDAPMessage.pointer, c_wchar_p],
        errcheck_pointer
    ],

    # struct berval** ldap_get_values_len(
    #   _In_  LDAP *ExternalHandle,
    #   _In_  LDAPMessage *Message,
    #   _In_  PCHAR attr
    # );
    [
        'ldap_get_values_len',
        'ldap_get_values_lenW',
        POINTER(LDAP_BERVAL.pointer),
        [LDAP.pointer, LDAPMessage.pointer, c_wchar_p],
        errcheck_pointer
    ],

    # LDAP* ldap_init(
    #   __in  PCHAR HostName,
    #   __in  ULONG PortNumber
    # );
    [
        'ldap_init',
        'ldap_initW',
        LDAP.pointer,
        [c_wchar_p, c_ulong],
        errcheck_pointer
    ],

    # VOID ldap_memfree(
    #   __in  PCHAR Block
    # );
    [
        'ldap_memfree',
        'ldap_memfreeW',
        None,
        [c_wchar_p],
        None
    ],

    # ULONG ldap_modify_s(
    #   _In_  LDAP *ld,
    #   _In_  PCHAR dn,
    #   _In_  LDAPMod *mods[]
    # );
    [
        'ldap_modify_s',
        'ldap_modify_sW',
        c_ulong,
        [LDAP.pointer, c_wchar_p, POINTER(LDAPMod.pointer)],
        errcheck_retcode
    ],

    # ULONG ldap_modify(
    #   _In_  LDAP *ld,
    #   _In_  PCHAR dn,
    #   _In_  LDAPMod *mods[]
    # );
    [
        'ldap_modify',
        'ldap_modifyW',
        c_ulong,
        [LDAP.pointer, c_wchar_p, POINTER(LDAPMod.pointer)],
        errcheck_sentinel
    ],

    # ULONG ldap_msgfree(
    #   __in  LDAPMessage *res
    # );
    [
        'ldap_msgfree',
        'ldap_msgfree',
        c_ulong,
        [LDAPMessage.pointer],
        None  # Always returns LDAP_SUCCESS
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
        [LDAP.pointer, LDAPMessage.pointer, BerElement.pointer],
        errcheck_pointer
    ],

    # LDAPMessage* ldap_next_entry(
    #   __in  LDAP *ld,
    #   __in  LDAPMessage *entry
    # );
    [
        'ldap_next_entry',
        'ldap_next_entry',
        LDAPMessage.pointer,
        [LDAP.pointer, LDAPMessage.pointer],
        errcheck_pointer
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
        [LDAP.pointer, c_ulong, c_ulong, LDAP_TIMEVAL.pointer,
         POINTER(LDAPMessage.pointer)],
        errcheck_sentinel
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
        [LDAP.pointer, c_wchar_p, c_ulong, c_wchar_p, POINTER(c_wchar_p),
         c_ulong, POINTER(LDAPMessage.pointer)],
        errcheck_retcode
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
        [LDAP.pointer, c_wchar_p, c_ulong, c_wchar_p, POINTER(c_wchar_p),
         c_ulong],
        errcheck_sentinel
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
        [LDAP.pointer, c_int, c_void_p],
        errcheck_retcode
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
        [LDAP.pointer, c_wchar_p, c_wchar_p],
        errcheck_retcode
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
        [LDAP.pointer, c_wchar_p, c_wchar_p],
        errcheck_sentinel
    ],

    # ULONG ldap_unbind_s(
    #   __in  LDAP *ld
    # );
    [
        'ldap_unbind_s',
        'ldap_unbind_s',
        c_ulong,
        [LDAP.pointer],
        errcheck_retcode
    ],

    # ULONG ldap_unbind[
    #   __in  LDAP *ld
    # ];
    [
        'ldap_unbind',
        'ldap_unbind',
        c_ulong,
        [LDAP.pointer],
        errcheck_retcode
    ],

    # ULONG ldap_value_free(
    #   PCHAR *vals
    # );
    [
        'ldap_value_free',
        'ldap_value_freeW',
        c_ulong,
        [POINTER(c_wchar_p)],
        errcheck_retcode
    ],

    # ULONG ldap_value_free_len(
    #   _In_  struct berval **vals
    # );
    [
        'ldap_value_free_len',
        'ldap_value_free_len',
        c_ulong,
        [POINTER(LDAP_BERVAL.pointer)],
        errcheck_retcode
    ],

    # ULONG LdapGetLastError(void);
    [
        'LdapGetLastError',
        'LdapGetLastError',
        c_ulong,
        [],
        None  # Hopefully can't fail
    ],
]


def initialize():
    from collections import namedtuple
    FunctionTemplate = namedtuple(
        'FunctionTemplate',
        ['exported_name', 'api_name', 'restype', 'argtypes', 'errcheck']
    )

    for exposed_function in exposed_functions:
        fn_data = FunctionTemplate(*exposed_function)

        # Retrieve Wldap32.dll exposed function and register its signature for
        # the ctypes module.
        fn_ldap = getattr(dll, fn_data.api_name)
        fn_ldap.restype = fn_data.restype
        fn_ldap.argtypes = fn_data.argtypes
        if fn_data.errcheck is not None:
            fn_ldap.errcheck = fn_data.errcheck

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
