PyWldap
=======

[![Build Status](https://travis-ci.org/icecrime/PyWldap.png)](https://travis-ci.org/icecrime/PyWldap)

Python wrapper over Windows Wldap32 library.

Overview
-------------

This package provides bindings and object oriented wrapper over Wldap32.dll (see [Microsoft MSDN page](http://msdn.microsoft.com/en-us/library/windows/desktop/aa366961.aspx) regarding this library).

**If you need to access LDAP from Python, you most likely want [Python LDAP](http://www.python-ldap.org/)**. However, Python LDAP is built over OpenLDAP which lacks binding methods other than `LDAP_AUTH_SIMPLE`.

Usage
-------------

    >>> import wldap
    >>> l = wldap.ldap('ldap://xxx')
    >>> l.bind_s('', '', wldap.LDAP_AUTH_DIGEST)
    >>> m = l.search_s('DN=world', wldap.LDAP_SCOPE_SUBTREE,
                       '(&(objectClass=user)(cn=icecrime))', ['someAttr'], 0)

License
-------------

Copyright 2013 Arnaud Porterie

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
