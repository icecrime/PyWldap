from collections import defaultdict
from ctypes import *
from itertools import takewhile

dll = cdll.Wldap32

# void ber_free(
#   __in  BerElement *pBerElement,
#   __in  INT fbuf
# );
dll.ber_free.restype = None
dll.ber_free.argtypes = [c_void_p, c_int]

# ULONG ldap_abandon(
#   __in   LDAP *ld,
#   __out  ULONG msgid
# );
dll.ldap_abandon.restype = c_ulong
dll.ldap_abandon.argtypes = [c_void_p, c_ulong]


# ULONG ldap_bind_s(
#   __in  LDAP *ld,
#   __in  PCHAR dn,
#   __in  PCHAR cred,
#   __in  ULONG method
# );
dll.ldap_bind_s.restype = c_ulong
dll.ldap_bind_s.argtypes = [c_void_p, c_char_p, c_char_p, c_ulong]

# ULONG ldap_bind(
#   __in  LDAP *ld,
#   __in  PCHAR dn,
#   __in  PCHAR cred,
#   __in  ULONG method
# );
dll.ldap_bind.restype = c_ulong
dll.ldap_bind.argtypes = [c_void_p, c_char_p, c_char_p, c_ulong]

# ULONG LDAPAPI ldap_cleanup(
#   HANDLE  hInstance
# );
dll.ldap_cleanup.restype = c_ulong
dll.ldap_cleanup.argtypes = [c_void_p]

# PCHAR ldap_first_attribute(
#   __in   LDAP *ld,
#   __in   LDAPMessage *entry,
#   __out  BerElement **ptr
# );
dll.ldap_first_attribute.restype = c_char_p
dll.ldap_first_attribute.argtypes = [c_void_p, c_void_p, POINTER(c_void_p)]

# LDAPMessage* ldap_first_entry(
#   __in  LDAP *ld,
#   __in  LDAPMessage *res
# );
dll.ldap_first_entry.restype = c_void_p
dll.ldap_first_entry.argtypes = [c_void_p, c_void_p]

# PCHAR* ldap_get_values(
#   __in  LDAP *ld,
#   __in  LDAPMessage *entry,
#   __in  PCHAR attr
# );
dll.ldap_get_values.restype = POINTER(c_char_p)
dll.ldap_get_values.argtypes = [c_void_p, c_void_p, c_char_p]

# ULONG ldap_get_option(
#   __in   LDAP *ld,
#   __in   int option,
#   __out  void *outvalue
# );
dll.ldap_get_option.restype = c_ulong
dll.ldap_get_option.argtypes = [c_void_p, c_int, c_void_p]

# LDAP* ldap_init(
#   __in  PCHAR HostName,
#   __in  ULONG PortNumber
# );
dll.ldap_init.restype = c_void_p
dll.ldap_init.argtypes = [c_char_p, c_ulong]

# VOID ldap_memfree(
#   __in  PCHAR Block
# );
dll.ldap_memfree.restype = None
dll.ldap_memfree.argtypes = [c_char_p]

# ULONG ldap_msgfree(
#   __in  LDAPMessage *res
# );
dll.ldap_msgfree.restype = c_ulong
dll.ldap_msgfree.argtypes = [c_void_p]

# PCHAR ldap_next_attribute(
#   __in     LDAP *ld,
#   __in     LDAPMessage *entry,
#   __inout  BerElement *ptr
# );
dll.ldap_next_attribute.restype = c_char_p
dll.ldap_next_attribute.argtypes = [c_void_p, c_void_p, c_void_p]

# LDAPMessage* ldap_next_entry(
#   __in  LDAP *ld,
#   __in  LDAPMessage *entry
# );
dll.ldap_next_entry.restype = c_void_p
dll.ldap_next_entry.argtypes = [c_void_p, c_void_p]

# ULONG ldap_result(
#   __in   LDAP *ld,
#   __in   ULONG msgid,
#   __in   ULONG all,
#   __in   struct l_timeval *timeout,
#   __out  LDAPMessage **res
# );
dll.ldap_result.restype = c_ulong
dll.ldap_result.argtypes = [c_void_p, c_ulong, c_ulong, c_void_p,
                            POINTER(c_void_p)]

# ULONG ldap_search_s(
#   __in   LDAP *ld,
#   __in   PCHAR base,
#   __in   ULONG scope,
#   __in   PCHAR filter,
#   __in   PCHAR attrs[],
#   __in   ULONG attrsonly,
#   __out  LDAPMessage **res
# );
dll.ldap_search_s.restype = c_ulong
dll.ldap_search_s.argtypes = [c_void_p, c_char_p, c_ulong, c_char_p,
                              POINTER(c_char_p), c_ulong, POINTER(c_void_p)]

# ULONG ldap_set_option(
#   __in  LDAP *ld,
#   __in  int option,
#   __in  void *invalue
# );
dll.ldap_set_option.restype = c_ulong
dll.ldap_set_option.argtypes = [c_void_p, c_int, c_void_p]

# ULONG ldap_simple_bind_s(
#   __in  LDAP *ld,
#   __in  PCHAR dn,
#   __in  PCHAR passwd
# );
dll.ldap_simple_bind_s.restype = c_ulong
dll.ldap_simple_bind_s.argtypes = [c_void_p, c_char_p, c_char_p]

# ULONG ldap_simple_bind(
#   __in  LDAP *ld,
#   __in  PCHAR dn,
#   __in  PCHAR passwd
# );
dll.ldap_simple_bind.restype = c_ulong
dll.ldap_simple_bind.argtypes = [c_void_p, c_char_p, c_char_p]

# ULONG ldap_unbind_s(
#   __in  LDAP *ld
# );
dll.ldap_unbind_s.restype = c_ulong
dll.ldap_unbind_s.argtypes = [c_void_p]

# ULONG ldap_unbind(
#   __in  LDAP *ld
# );
dll.ldap_unbind.restype = c_ulong
dll.ldap_unbind.argtypes = [c_void_p]

# ULONG ldap_value_free(
#   PCHAR *vals
# );
dll.ldap_value_free.restype = c_ulong
dll.ldap_value_free.argtypes = [POINTER(c_char_p)]

##############################################################################

LDAP_PORT                       = 389

##############################################################################

LDAP_SCOPE_BASE                 = 0x00
LDAP_SCOPE_ONELEVEL             = 0x01
LDAP_SCOPE_SUBTREE              = 0x02

##############################################################################

LDAP_AUTH_SIMPLE                = 0x80L
LDAP_AUTH_SASL                  = 0x83L
LDAP_AUTH_OTHERKIND             = 0x86L
LDAP_AUTH_SICILY                = (LDAP_AUTH_OTHERKIND | 0x0200)
LDAP_AUTH_MSN                   = (LDAP_AUTH_OTHERKIND | 0x0800)
LDAP_AUTH_NTLM                  = (LDAP_AUTH_OTHERKIND | 0x1000)
LDAP_AUTH_DPA                   = (LDAP_AUTH_OTHERKIND | 0x2000)
LDAP_AUTH_NEGOTIATE             = (LDAP_AUTH_OTHERKIND | 0x0400)
LDAP_AUTH_SSPI                  =  LDAP_AUTH_NEGOTIATE
LDAP_AUTH_DIGEST                = (LDAP_AUTH_OTHERKIND | 0x4000)
LDAP_AUTH_EXTERNAL              = (LDAP_AUTH_OTHERKIND | 0x0020)

##############################################################################

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

##############################################################################

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

##############################################################################

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
        if dll and hasattr(self, 'raw_values'):
            dll.ldap_value_free(self.raw_values)

    def __str__(self):
        return str((self.name, self.values))

    @property
    def values(self):
        return takewhile(bool, self.raw_values)

##############################################################################

class MessageEntryIterator(object):
    """Implements iteration over LDAPMessage* attributes."""

    def __init__(self, ldap, message):
        """Construct a new MessageEntryIterator instance.

        Args:
            ldap: low level LDAP* pointer
            message: the Message instance which attributes we want to extract
        """
        self._l = ldap
        self._message = message
        self._berElem = c_void_p()
        self._attribute = dll.ldap_first_attribute(self._l, self._message,
                                                   byref(self._berElem))

    def __del__(self):
        # Cf MSDN ldap_first_attribute documentation: 'When you have finished
        # stepping through a list of attributes and ptr is non-NULL, free the
        # pointer by calling ber_free( ptr, 0 ). Be aware that you must pass
        # the second parameter as 0 (zero) in this call.
        if dll and hasattr(self, '_berElem') and self._berElem:
            dll.ber_free(self._berElem, 0)

    def next(self):
        # Because of the first / next API asymmetry, we're always 'off by one',
        # so the previously fetched value is tested before moving on.
        if not self._attribute:
            raise StopIteration

        # Wrap the previously fetched value in a MessageAttribute object before
        # going with the iteration.
        current = MessageAttribute(self._l, self._message, self._attribute)
        self._attribute = dll.ldap_next_attribute(self._l, self._message,
                                                  self._berElem)
        return current


class MessageEntry(object):
    """MessageEntry."""

    def __init__(self, ldap, messageEntry):
        """Construct a new MessageEntry instance.

        Args:
            ldap: low level LDAP* pointer
            entry: a LDAPMessage* as obtained through ldap_(first|next)_entry
        """
        self._l = ldap
        self._messageEntry = messageEntry

    def __iter__(self):
        return MessageEntryIterator(self._l, self._messageEntry)

    def __getitem__(self, attributeName):
        return MessageAttribute(self._l, self._messageEntry, attributeName)

##############################################################################

class MessageIterator(object):
    """Implements iteration over LDAPMessage* entries."""

    def __init__(self, ldap, message):
        """Construct a new MessageIterator instance.

        Args:
            ldap: low level LDAP* pointer
            message: a LDAPMessage* as obtained, for example, through search
        """
        self._l = ldap
        self._messageEntry = dll.ldap_first_entry(self._l, message)

    def next(self):
        # Because of the first / next API asymmetry, we're always 'off by one',
        # so the previously fetched value is tested before moving on.
        if not self._messageEntry:
            raise StopIteration

        # Wrap the previously fetched value in a MessageEntry object before
        # going with the iteration.
        current = MessageEntry(self._l, self._messageEntry)
        self._messageEntry = dll.ldap_next_entry(self._l, self._messageEntry)
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
        if dll and hasattr(self, '_message'):
            dll.ldap_msgfree(self._message)

    def __iter__(self):
        return MessageIterator(self._ldap, self._message)

###############################################################################

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

    def bind(self, dn, cred, method):
        return dll.ldap_bind(self._l, dn, cred, method)

    def bind_s(self, dn, cred, method):
        return dll.ldap_bind_s(self._l, dn, cred, method)

    def _search(self, f, base, scope, filt, attr, attronly):
        result = c_void_p()

        # Convert attribute list to a C, nul-terminated string array.
        attr = attr + [None]
        attr = (c_char_p * len(attr))(*attr)

        # Last parameter is a LDAPMessage**, thus the need for a byref().
        ret = f(self._l, base, scope, filt, attr, attronly, byref(result))
        return not ret and Message(self._l, result) or None

    def search(self, base, scope, filt, attr, attronly):
        return self._search(dll.ldap_search, base, scope, filt, attr, attronly)

    def search_s(self, base, scope, filt, attr, attronly):
        return self._search(dll.ldap_search_s, base, scope, filt, attr, attronly)

    def simple_bind(self, dn, passwd):
        return dll.ldap_simple_bind(self._l, dn, passwd)

    def simple_bind_s(self, dn, passwd):
        return dll.ldap_simple_bind_s(self._l, dn, passwd)

    def unbind(self):
        return dll.ldap_unbind(self._l)

    def unbind_s(self):
        return dll.ldap_unbind_s(self._l)


def parseMessage(message):
    """Builds a dictionary for the provided Message instance by iterating over
    every attribute of every entry.

    Args:
        message: a Message instance as returned, for example, by searching
    """
    output = {}
    for entry in message:
        output.update({a.name: list(a.values) for a in entry})
    return output
