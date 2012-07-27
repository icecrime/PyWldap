=======
PyWldap
=======

Python wrapper over Windows Wldap32 library.

Overview
-------------

This package provides bindings and object oriented wrapper over Wldap32.dll (see [Microsoft MSDN page](http://msdn.microsoft.com/en-us/library/windows/desktop/aa366961(v=vs.85).aspx>) regarding this library).

**If you need to access LDAP from Python, you most likely want [Python LDAP](http://www.python-ldap.org/)**. However, Python LDAP is built over OpenLDAP, which lacks binding methods other than LDAP\_AUTH\_SIMPLE.

Usage
-------------

    >>> import Wldap
    >>> l = Wldap.ldap('ldap://xxx')
    >>> l.bind_s(method=Wldap.LDAP_AUTH_DIGEST)
    >>> m = l.search_s('DN=world', Wldap.LDAP_SCOPE_SUBTREE,
                       '(&(objectClass=user)(cn=plop))', ['someAttr'], 0)
