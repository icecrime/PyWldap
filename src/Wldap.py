from collections import defaultdict
from ctypes import *
from itertools import takewhile

dll = cdll.Wldap32

# LDAP* ldap_init(
#   __in  PCHAR HostName,
#   __in  ULONG PortNumber
# );
dll.ldap_bind_s.restype = c_void_p
dll.ldap_init.argtypes = [c_char_p, c_ulong]

# ULONG ldap_bind_s(
#   __in  LDAP *ld,
#   __in  PCHAR dn,
#   __in  PCHAR cred,
#   __in  ULONG method
# );
dll.ldap_bind_s.restype = c_ulong
dll.ldap_bind_s.argtypes = [c_void_p, c_char_p, c_char_p, c_ulong]

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

# PCHAR* ldap_get_values(
#   __in  LDAP *ld,
#   __in  LDAPMessage *entry,
#   __in  PCHAR attr
# );
dll.ldap_get_values.restype = POINTER(c_char_p)
dll.ldap_get_values.argtypes = [c_void_p, c_void_p, c_char_p]

# LDAPMessage* ldap_first_entry(
#   __in  LDAP *ld,
#   __in  LDAPMessage *res
# );
dll.ldap_first_entry.restype = c_void_p
dll.ldap_first_entry.argtypes = [c_void_p, c_void_p]

# LDAPMessage* ldap_next_entry(
#   __in  LDAP *ld,
#   __in  LDAPMessage *entry
# );
dll.ldap_next_entry.restype = c_void_p
dll.ldap_next_entry.argtypes = [c_void_p, c_void_p]

# ULONG ldap_msgfree(
#   __in  LDAPMessage *res
# );
dll.ldap_msgfree.restype = c_ulong
dll.ldap_msgfree.argtypes = [c_void_p]

# PCHAR ldap_first_attribute(
#   __in   LDAP *ld,
#   __in   LDAPMessage *entry,
#   __out  BerElement **ptr
# );
dll.ldap_first_attribute.restype = c_char_p
dll.ldap_first_attribute.argtypes = [c_void_p, c_void_p, POINTER(c_void_p)]

# PCHAR ldap_next_attribute(
#   __in     LDAP *ld,
#   __in     LDAPMessage *entry,
#   __inout  BerElement *ptr
# );
dll.ldap_next_attribute.restype = c_char_p
dll.ldap_next_attribute.argtypes = [c_void_p, c_void_p, c_void_p]

# void ber_free(
#   __in  BerElement *pBerElement,
#   __in  INT fbuf
# );
dll.ber_free.argtypes = [c_void_p, c_int]

# VOID ldap_memfree(
#   __in  PCHAR Block
# );
dll.ldap_memfree.argtypes = [c_char_p]

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

    def bind_s(self, dn=None, cred=None, method):
        return dll.ldap_bind_s(self._l, dn, cred, method)

    def search_s(self, base, scope, filt, attr, attronly):
        result = c_void_p()

        # Convert attribute list to a C, nul-terminated string array.
        attr = attr + [None]
        attr = (c_char_p * len(attr))(*attr)

        # Last parameter is a LDAPMessage**, thus the need for a byref().
        ret = dll.ldap_search_s(self._l, base, scope, filt, attr, attronly,
                                byref(result))
        return Message(self._l, result) if not ret else None


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
