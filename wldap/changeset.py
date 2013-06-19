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

from ctypes import addressof

from wldap.wldap32_structures import LDAPMod


class Changeset(object):
    """The Changeset class describes the list of operation to apply in a modify
    operation.

    Example use:

    >>> changeset = Changeset()
    >>> changeset.add('attr1', ['val1', 'val2'])   # Add val1 & val2 to attr1
    ...          .add_binary('attr2', ['b_val1'])  # Add b_val1 to attr2
    ...          .delete('attr3', None)            # Delete attr3
    """

    def __init__(self):
        self.changes = []

    def _append(self, mod_op, mod_type, **kwargs):
        self.changes.append(LDAPMod(mod_op, mod_type, **kwargs))
        return self

    def add(self, attr, values):
        """Record an operation to add string data to the changeset.

        Args:
            attr: the name of the attribute to which values should be added
            values: a sequence of strings to be appended to the existing values
                in the attribute
        """
        return self._append(LDAPMod.LDAP_MOD_ADD, attr, str_values=values)

    def add_binary(self, attr, values):
        """Record an operation to add binary data the changeset.

        Args:
            attr: the name of the attribute to which values should be added
            values: a sequence of bytes to be appended to the existing values
                in the attribute
        """
        return self._append(LDAPMod.LDAP_MOD_ADD, attr, bin_values=values)

    def delete(self, attr, values):
        """Record an operation to delete string data to the changeset.

        Remark: ldap_modify* deletes the entire attribute when `values` is set
        to None.

        Args:
            attr: the name of the attribute from which values should be removed
            values: a sequence of strings to be deleted from the current
                attribute values
        """
        return self._append(LDAPMod.LDAP_MOD_DELETE, attr, str_values=values)

    def delete_binary(self, attr, values):
        """Record an operation to delete binary data to the changeset.

        Remark: ldap_modify* deletes the entire attribute when `values` is set
        to None.

        Args:
            attr: the name of the attribute from which values should be removed
            values: a sequence of bytes to be deleted from the current
                attribute values
        """
        return self._append(LDAPMod.LDAP_MOD_DELETE, attr, bin_values=values)

    def replace(self, attr, values):
        """Record an operation to replace string data to the changeset.

        Remark: ldap_modify* does not delete the attribute when `values` is set
        to None.

        Args:
            attr: the name of the attribute where values should be replaced
            values: a sequence of strings to replace the current attribute
                values with
        """
        return self._append(LDAPMod.LDAP_MOD_REPLACE, attr, str_values=values)

    def replace_binary(self, attr, values):
        """Record an operation to replace binary data to the changeset.

        Remark: ldap_modify* does not delete the attribute when `values` is set
        to None.

        Args:
            attr: the name of the attribute where values should be replaced
            values: a sequence of bytes to replace the current attribute
                values with
        """
        return self._append(LDAPMod.LDAP_MOD_REPLACE, attr, bin_values=values)

    def to_api_param(self):
        """Convert the changeset to a C nul-terminated array of LDAPMod*
        suitable to pass to Wldap32 ldap_add* and ldap_modify* API functions.
        """
        if self.changes == []:
            return None
        return [LDAPMod.pointer(item) for item in self.changes] + [None]
