PyWldap Changelog
=================

Version 0.3.0
-------------

Released on June 19th, 2013

- Complete test coverage
- Proper error checking: calls may now raise `wldap.LDAPError` exceptions
- Add support for binary attribute values (thanks @ereOn!)
- Add support for asychronous requests (see `wldap.Future` object)
- Add support for modification requests (see `wldap.Changeset` object)
- Fix `parse_message` to return a list of dictionary (one for each message entry)

Version 0.2.1
-------------

Released on May 27th, 2013

- Python 3.x compat: use __next__ for iterators

Version 0.2.0
-------------

Released on May 26th, 2013

- Switch to full unicode
    - Breaking for Python 2.x code: returned values are now of type `unicode`
    - Transparent for Python 3.x code where unicode is the default
- Rename `parseMessage` to `parse_message` (PEP8 compliance)


Version 0.1.0
-------------

Released on February 27th, 2013
