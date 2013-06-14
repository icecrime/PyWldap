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

from wldap.exceptions import TimeoutError


class Future(object):
    """The Future holds an asynchronous operation result.

    Its design is loosely inspired by PEP-3148: it should comply as described
    for the cancel(), cancelled(), exception(), done() and result() operations.
    """

    def __init__(self, ldap, msgid):
        self._cancelled = False
        self._exception = None
        self._ldap = ldap
        self._msgid = msgid
        self._result = None

    def cancel(self):
        self._cancelled = self._ldap.abandon(self._msgid)
        return self._cancelled

    def cancelled(self):
        return self._cancelled

    def exception(self, timeout_seconds=None):
        self.result(timeout_seconds)
        return self._exception

    def done(self):
        # Take a peek at the result with a timeout value of 0. This can't raise
        # because _get_result catches and store any exception.
        if self._exception or self._result:
            return True
        return self._get_result(0) is not None

    def _get_result(self, timeout_seconds=None):
        try:
            LDAP_MSG_ALL = 0x1
            ret = self._ldap.result(self._msgid, LDAP_MSG_ALL, timeout_seconds)
            if ret is not None:  # Store the result if it isn't a timeout
                self._result = ret
            return ret
        except Exception as exc:
            self._exception = exc

    def result(self, timeout_seconds=None):
        if not (self._exception or self._result):
            if self._get_result(timeout_seconds) is None:
                raise TimeoutError()
        if self._exception:
            raise self._exception
        return self._result

    def running(self):
        # I don't get the PEP on this one: "return True if the call is
        # currently being executed and cannot be cancelled". Well, the future
        # is either completed or can be cancelled, so that's always False.
        return False
