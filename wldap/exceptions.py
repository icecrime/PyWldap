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


class Error(Exception):
    """Base exception type for the wldap package."""
    pass


class LdapError(Error):
    """Exception type for Wldap32 errors."""

    def __init__(self, error_code=None):
        from wldap.wldap32_dll import LdapGetLastError, ldap_err2string
        code = error_code or LdapGetLastError()
        super(LdapError, self).__init__(ldap_err2string(code), code)


class TimeoutError(Error):
    """Raised by Future.result() and Future.exceptions(), (loosely) as
    described in PEP-3148.
    """
    pass
