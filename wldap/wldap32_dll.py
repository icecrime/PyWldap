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

_dll = cdll.Wldap32

# void ber_free(
#   __in  BerElement *pBerElement,
#   __in  INT fbuf
# );
ber_free = _dll.ber_free
ber_free.restype = None
ber_free.argtypes = [c_void_p, c_int]

# ULONG ldap_abandon(
#   __in   LDAP *ld,
#   __out  ULONG msgid
# );
ldap_abandon = _dll.ldap_abandon
ldap_abandon.restype = c_ulong
ldap_abandon.argtypes = [c_void_p, c_ulong]

# ULONG ldap_bind_s(
#   __in  LDAP *ld,
#   __in  PCHAR dn,
#   __in  PCHAR cred,
#   __in  ULONG method
# );
ldap_bind_s = _dll.ldap_bind_sW
ldap_bind_s.restype = c_ulong
ldap_bind_s.argtypes = [c_void_p, c_wchar_p, c_wchar_p, c_ulong]

# ULONG ldap_bind(
#   __in  LDAP *ld,
#   __in  PCHAR dn,
#   __in  PCHAR cred,
#   __in  ULONG method
# );
ldap_bind = _dll.ldap_bindW
ldap_bind.restype = c_ulong
ldap_bind.argtypes = [c_void_p, c_wchar_p, c_wchar_p, c_ulong]

# ULONG LDAPAPI ldap_cleanup(
#   HANDLE  hInstance
# );
ldap_cleanup = _dll.ldap_cleanup
ldap_cleanup.restype = c_ulong
ldap_cleanup.argtypes = [c_void_p]

# PCHAR ldap_first_attribute(
#   __in   LDAP *ld,
#   __in   LDAPMessage *entry,
#   __out  BerElement **ptr
# );
ldap_first_attribute = _dll.ldap_first_attributeW
ldap_first_attribute.restype = c_wchar_p
ldap_first_attribute.argtypes = [c_void_p, c_void_p, POINTER(c_void_p)]

# LDAPMessage* ldap_first_entry(
#   __in  LDAP *ld,
#   __in  LDAPMessage *res
# );
ldap_first_entry = _dll.ldap_first_entry
ldap_first_entry.restype = c_void_p
ldap_first_entry.argtypes = [c_void_p, c_void_p]

# PCHAR* ldap_get_values(
#   __in  LDAP *ld,
#   __in  LDAPMessage *entry,
#   __in  PCHAR attr
# );
ldap_get_values = _dll.ldap_get_valuesW
ldap_get_values.restype = POINTER(c_wchar_p)
ldap_get_values.argtypes = [c_void_p, c_void_p, c_wchar_p]

# ULONG ldap_get_option(
#   __in   LDAP *ld,
#   __in   int option,
#   __out  void *outvalue
# );
ldap_get_option = _dll.ldap_get_option
ldap_get_option.restype = c_ulong
ldap_get_option.argtypes = [c_void_p, c_int, c_void_p]

# LDAP* ldap_init(
#   __in  PCHAR HostName,
#   __in  ULONG PortNumber
# );
ldap_init = _dll.ldap_initW
ldap_init.restype = c_void_p
ldap_init.argtypes = [c_wchar_p, c_ulong]

# VOID ldap_memfree(
#   __in  PCHAR Block
# );
ldap_memfree = _dll.ldap_memfreeW
ldap_memfree.restype = None
ldap_memfree.argtypes = [c_wchar_p]

# ULONG ldap_msgfree(
#   __in  LDAPMessage *res
# );
ldap_msgfree = _dll.ldap_msgfree
ldap_msgfree.restype = c_ulong
ldap_msgfree.argtypes = [c_void_p]

# PCHAR ldap_next_attribute(
#   __in     LDAP *ld,
#   __in     LDAPMessage *entry,
#   __inout  BerElement *ptr
# );
ldap_next_attribute = _dll.ldap_next_attributeW
ldap_next_attribute.restype = c_wchar_p
ldap_next_attribute.argtypes = [c_void_p, c_void_p, c_void_p]

# LDAPMessage* ldap_next_entry(
#   __in  LDAP *ld,
#   __in  LDAPMessage *entry
# );
ldap_next_entry = _dll.ldap_next_entry
ldap_next_entry.restype = c_void_p
ldap_next_entry.argtypes = [c_void_p, c_void_p]

# ULONG ldap_result(
#   __in   LDAP *ld,
#   __in   ULONG msgid,
#   __in   ULONG all,
#   __in   struct l_timeval *timeout,
#   __out  LDAPMessage **res
# );
ldap_result = _dll.ldap_result
ldap_result.restype = c_ulong
ldap_result.argtypes = [c_void_p, c_ulong, c_ulong, c_void_p,
                        POINTER(c_void_p)]

# ULONG ldap_search(
#   _In_  LDAP *ld,
#   _In_  PCHAR base,
#   _In_  ULONG scope,
#   _In_  PCHAR filter,
#   _In_  PCHAR attrs[],
#   _In_  ULONG attrsonly
# );
ldap_search = _dll.ldap_searchW
ldap_search.restype = c_ulong
ldap_search.argtypes = [c_void_p, c_wchar_p, c_ulong, c_wchar_p,
                        POINTER(c_wchar_p), c_ulong]

# ULONG ldap_search_s(
#   __in   LDAP *ld,
#   __in   PCHAR base,
#   __in   ULONG scope,
#   __in   PCHAR filter,
#   __in   PCHAR attrs[],
#   __in   ULONG attrsonly,
#   __out  LDAPMessage **res
# );
ldap_search_s = _dll.ldap_search_sW
ldap_search_s.restype = c_ulong
ldap_search_s.argtypes = [c_void_p, c_wchar_p, c_ulong, c_wchar_p,
                          POINTER(c_wchar_p), c_ulong, POINTER(c_void_p)]

# ULONG ldap_set_option(
#   __in  LDAP *ld,
#   __in  int option,
#   __in  void *invalue
# );
ldap_set_option = _dll.ldap_set_option
ldap_set_option.restype = c_ulong
ldap_set_option.argtypes = [c_void_p, c_int, c_void_p]

# ULONG ldap_simple_bind_s(
#   __in  LDAP *ld,
#   __in  PCHAR dn,
#   __in  PCHAR passwd
# );
ldap_simple_bind_s = _dll.ldap_simple_bind_sW
ldap_simple_bind_s.restype = c_ulong
ldap_simple_bind_s.argtypes = [c_void_p, c_wchar_p, c_wchar_p]

# ULONG ldap_simple_bind(
#   __in  LDAP *ld,
#   __in  PCHAR dn,
#   __in  PCHAR passwd
# );
ldap_simple_bind = _dll.ldap_simple_bindW
ldap_simple_bind.restype = c_ulong
ldap_simple_bind.argtypes = [c_void_p, c_wchar_p, c_wchar_p]

# ULONG ldap_unbind_s(
#   __in  LDAP *ld
# );
ldap_unbind_s = _dll.ldap_unbind_s
ldap_unbind_s.restype = c_ulong
ldap_unbind_s.argtypes = [c_void_p]

# ULONG ldap_unbind(
#   __in  LDAP *ld
# );
ldap_unbind = _dll.ldap_unbind
ldap_unbind.restype = c_ulong
ldap_unbind.argtypes = [c_void_p]

# ULONG ldap_value_free(
#   PCHAR *vals
# );
ldap_value_free = _dll.ldap_value_freeW
ldap_value_free.restype = c_ulong
ldap_value_free.argtypes = [POINTER(c_wchar_p)]

###############################################################################

LDAP_PORT                       = 389

###############################################################################

LDAP_SCOPE_BASE                 = 0x00
LDAP_SCOPE_ONELEVEL             = 0x01
LDAP_SCOPE_SUBTREE              = 0x02

###############################################################################

LDAP_AUTH_SIMPLE                = 0x80
LDAP_AUTH_SASL                  = 0x83
LDAP_AUTH_OTHERKIND             = 0x86
LDAP_AUTH_SICILY                = (LDAP_AUTH_OTHERKIND | 0x0200)
LDAP_AUTH_MSN                   = (LDAP_AUTH_OTHERKIND | 0x0800)
LDAP_AUTH_NTLM                  = (LDAP_AUTH_OTHERKIND | 0x1000)
LDAP_AUTH_DPA                   = (LDAP_AUTH_OTHERKIND | 0x2000)
LDAP_AUTH_NEGOTIATE             = (LDAP_AUTH_OTHERKIND | 0x0400)
LDAP_AUTH_SSPI                  =  LDAP_AUTH_NEGOTIATE
LDAP_AUTH_DIGEST                = (LDAP_AUTH_OTHERKIND | 0x4000)
LDAP_AUTH_EXTERNAL              = (LDAP_AUTH_OTHERKIND | 0x0020)

###############################################################################

LDAP_OPT_API_INFO               = 0x00
LDAP_OPT_API_FEATURE_INFO       = 0x15
LDAP_OPT_AREC_EXCLUSIVE         = 0x98
LDAP_OPT_AUTO_RECONNECT         = 0x91
LDAP_OPT_CACHE_ENABLE           = 0x0F
LDAP_OPT_CACHE_FN_PTRS          = 0x0D
LDAP_OPT_CACHE_STRATEGY         = 0x0E
LDAP_OPT_CLIENT_CERTIFICATE     = 0x80
LDAP_OPT_DEREF                  = 0x02
LDAP_OPT_DESC                   = 0x01
LDAP_OPT_DNSDOMAIN_NAME         = 0x3B
LDAP_OPT_ENCRYPT                = 0x96
LDAP_OPT_ERROR_NUMBER           = 0x31
LDAP_OPT_ERROR_STRING           = 0x32
LDAP_OPT_FAST_CONCURRENT_BIND   = 0x41
LDAP_OPT_GETDSNAME_FLAGS        = 0x3D
LDAP_OPT_HOST_NAME              = 0x30
LDAP_OPT_HOST_REACHABLE         = 0x3E
LDAP_OPT_IO_FN_PTRS             = 0x0B
LDAP_OPT_PING_KEEP_ALIVE        = 0x36
LDAP_OPT_PING_LIMIT             = 0x38
LDAP_OPT_PING_WAIT_TIME         = 0x37
LDAP_OPT_PROMPT_CREDENTIALS     = 0x3F
LDAP_OPT_PROTOCOL_VERSION       = 0x11
LDAP_OPT_VERSION                = 0x11
LDAP_OPT_REBIND_ARG             = 0x07
LDAP_OPT_REBIND_FN              = 0x06
LDAP_OPT_REF_DEREF_CONN_PER_MSG = 0x94
LDAP_OPT_REFERRAL_CALLBACK      = 0x70
LDAP_OPT_REFERRAL_HOP_LIMIT     = 0x10
LDAP_OPT_REFERRALS              = 0x08
LDAP_OPT_RESTART                = 0x09
LDAP_OPT_ROOTDSE_CACHE          = 0x9A
LDAP_OPT_SASL_METHOD            = 0x97
LDAP_OPT_SECURITY_CONTEXT       = 0x99
LDAP_OPT_SEND_TIMEOUT           = 0x42
LDAP_OPT_SCH_FLAGS              = 0x43
LDAP_OPT_SOCKET_BIND_ADDRESSES  = 0x44
LDAP_OPT_SERVER_CERTIFICATE     = 0x81
LDAP_OPT_SERVER_ERROR           = 0x33
LDAP_OPT_SERVER_EXT_ERROR       = 0x34
LDAP_OPT_SIGN                   = 0x95
LDAP_OPT_SIZELIMIT              = 0x03
LDAP_OPT_SSL                    = 0x0A
LDAP_OPT_SSL_INFO               = 0x93
LDAP_OPT_SSPI_FLAGS             = 0x92
LDAP_OPT_TCP_KEEPALIVE          = 0x40
LDAP_OPT_THREAD_FN_PTRS         = 0x05
LDAP_OPT_TIMELIMIT              = 0x04

###############################################################################

LDAP_ADMIN_LIMIT_EXCEEDED       = 0x0b
LDAP_AFFECTS_MULTIPLE_DSAS      = 0x47
LDAP_ALIAS_DEREF_PROBLEM        = 0x24
LDAP_ALIAS_PROBLEM              = 0x21
LDAP_ALREADY_EXISTS             = 0x44
LDAP_ATTRIBUTE_OR_VALUE_EXISTS  = 0x14
LDAP_AUTH_METHOD_NOT_SUPPORTED  = 0x07
LDAP_AUTH_UNKNOWN               = 0x56
LDAP_BUSY                       = 0x33
LDAP_CLIENT_LOOP                = 0x60
LDAP_COMPARE_FALSE              = 0x05
LDAP_COMPARE_TRUE               = 0x06
LDAP_CONFIDENTIALITY_REQUIRED   = 0x0d
LDAP_CONNECT_ERROR              = 0x5b
LDAP_CONSTRAINT_VIOLATION       = 0x13
LDAP_CONTROL_NOT_FOUND          = 0x5d
LDAP_DECODING_ERROR             = 0x54
LDAP_ENCODING_ERROR             = 0x53
LDAP_FILTER_ERROR               = 0x57
LDAP_INAPPROPRIATE_AUTH         = 0x30
LDAP_INAPPROPRIATE_MATCHING     = 0x12
LDAP_INSUFFICIENT_RIGHTS        = 0x32
LDAP_INVALID_CREDENTIALS        = 0x31
LDAP_INVALID_DN_SYNTAX          = 0x22
LDAP_INVALID_SYNTAX             = 0x15
LDAP_IS_LEAF                    = 0x23
LDAP_LOCAL_ERROR                = 0x52
LDAP_LOOP_DETECT                = 0x36
LDAP_MORE_RESULTS_TO_RETURN     = 0x5f
LDAP_NAMING_VIOLATION           = 0x40
LDAP_NO_MEMORY                  = 0x5a
LDAP_NO_OBJECT_CLASS_MODS       = 0x45
LDAP_NO_RESULTS_RETURNED        = 0x5e
LDAP_NO_SUCH_ATTRIBUTE          = 0x10
LDAP_NO_SUCH_OBJECT             = 0x20
LDAP_NOT_ALLOWED_ON_NONLEAF     = 0x42
LDAP_NOT_ALLOWED_ON_RDN         = 0x43
LDAP_NOT_SUPPORTED              = 0x5c
LDAP_OBJECT_CLASS_VIOLATION     = 0x41
LDAP_OPERATIONS_ERROR           = 0x01
LDAP_OTHER                      = 0x50
LDAP_PARAM_ERROR                = 0x59
LDAP_PARTIAL_RESULTS            = 0x09
LDAP_PROTOCOL_ERROR             = 0x02
LDAP_REFERRAL                   = 0x0a
LDAP_REFERRAL_LIMIT_EXCEEDED    = 0x61
LDAP_REFERRAL_V2                = 0x09
LDAP_RESULTS_TOO_LARGE          = 0x46
LDAP_SERVER_DOWN                = 0x51
LDAP_SIZELIMIT_EXCEEDED         = 0x04
LDAP_STRONG_AUTH_REQUIRED       = 0x08
LDAP_SUCCESS                    = 0x00
LDAP_TIMELIMIT_EXCEEDED         = 0x03
LDAP_TIMEOUT                    = 0x55
LDAP_UNAVAILABLE                = 0x34
LDAP_UNAVAILABLE_CRIT_EXTENSION = 0x0c
LDAP_UNDEFINED_TYPE             = 0x11
LDAP_UNWILLING_TO_PERFORM       = 0x35
LDAP_USER_CANCELLED             = 0x58
LDAP_VIRTUAL_LIST_VIEW_ERROR    = 0x4c
