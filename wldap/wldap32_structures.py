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

from ctypes import POINTER, Structure, Union, addressof, cast
from ctypes import c_char, c_long, c_ulong, c_wchar_p
import sys


class BerElement(Structure):
    """The BerElement structure is opaque but allows us to provide better type
    safety upon API calls by using POINTER(BerElement) rather than c_void_p.
    """
    pass

# Nested 'typedef' for pointer type
BerElement.pointer = POINTER(BerElement)


class LDAP(Structure):
    """The LDAP structure is opaque but allows us to provide better type safety
    upon API calls by using POINTER(LDAP) rather than c_void_p.
    """
    pass

# Nested 'typedef' for pointer type
LDAP.pointer = POINTER(LDAP)


class LDAP_BERVAL(Structure):
    _fields_ = [
        ('bv_len', c_ulong),
        ('bv_val', POINTER(c_char)),  # Not c_char_p (which is null terminated)
    ]

    @staticmethod
    def from_value(value):
        # This function must be called with either an str object (in 2.x) or a
        # bytes object (in 3.x), but not with a string: if it happens to be a
        # unicode string, then the length won't match the byte length.
        return LDAP_BERVAL(len(value), cast(value, POINTER(c_char)))

# Nested 'typedef' for pointer type
LDAP_BERVAL.pointer = POINTER(LDAP_BERVAL)


class LDAP_TIMEVAL(Structure):
    _fields_ = [
        ('tv_sec', c_long),
        ('tv_usec', c_long),
    ]

    @staticmethod
    def from_fractional_seconds(fractional_seconds):
        from math import modf
        frac, secs = modf(fractional_seconds)
        return LDAP_TIMEVAL(int(secs), int(frac * 10e-6))

# Nested 'typedef' for pointer type
LDAP_TIMEVAL.pointer = POINTER(LDAP_TIMEVAL)


class LDAPMessage(Structure):
    """The LDAP structure is opaque but allows us to provide better type safety
    upon API calls by using POINTER(LDAPMessage) rather than c_void_p.
    """
    pass

# Nested 'typedef' for pointer type
LDAPMessage.pointer = POINTER(LDAPMessage)


class LDAPMod(Structure):

    LDAP_MOD_ADD     = 0x00
    LDAP_MOD_DELETE  = 0x01
    LDAP_MOD_REPLACE = 0x02
    LDAP_MOD_BVALUES = 0x80

    class mod_vals_union(Union):
        _fields_ = [
            ('modv_strvals', POINTER(c_wchar_p)),
            ('modv_bvals', POINTER(LDAP_BERVAL.pointer)),
        ]

    _fields_ = [
        ('mod_op', c_ulong),
        ('mod_type', c_wchar_p),
        ('mod_vals', mod_vals_union),
    ]

    def __init__(self, op, attribute, **kwargs):
        bin_values = kwargs.get('bin_values')
        str_values = kwargs.get('str_values')
        if (str_values is None) == (bin_values is None):
            raise ValueError('Provide either str_values or bin_values')

        # We _always_ use LDAP_MOD_BVALUES to specify binary values, which
        # helps us to simply ignore the type of the provided values.
        self.mod_op = op
        if bin_values:
            self.mod_op |= self.LDAP_MOD_BVALUES
        self.mod_type = attribute

        # If string values are provided, we need values as a C nul-terminated
        # string array. If binary values are provided, we need values as a C
        # nul-terminated LDAP_BERVAL* array.
        if 'str_values' in kwargs:
            values = str_values + [None]
            values = (c_wchar_p * len(values))(*values)
            self.mod_vals.modv_strvals = values or None
        elif 'bin_values' in kwargs:
            values = [LDAP_BERVAL.from_value(value) for value in bin_values]
            values = [addressof(item) for item in values] + [None]
            self.mod_vals.modv_bvals = values or None

# Nested 'typedef' for pointer type
LDAPMod.pointer = POINTER(LDAPMod)
