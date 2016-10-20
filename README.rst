============
web.security
============

    © 2009-2016 Alice Bevan-McGregor and contributors.

..

    https://github.com/marrow/web.security

..

    |latestversion| |ghtag| |masterstatus| |mastercover| |masterreq| |ghwatch| |ghstar|



Introduction
============

This package combines a number of smaller components to provide the parts to build the security model for your own
WebCore applications.


Installation
============

Installing ``web.security`` is easy, just execute the following in a terminal::

    pip install web.security

**Note:** We *strongly* recommend always using a container, virtualization, or sandboxing environment of some kind when
developing using Python; installing things system-wide is yucky (for a variety of reasons) nine times out of ten.  We
prefer light-weight `virtualenv <https://virtualenv.pypa.io/en/latest/virtualenv.html>`__, others prefer solutions as
robust as `Vagrant <http://www.vagrantup.com>`__.

If you add ``web.security`` to the ``install_requires`` argument of the call to ``setup()`` in your
application's ``setup.py`` file, this suite will be automatically installed and made available when your own
application or library is installed.  We recommend using "less than" version numbers to ensure there are no
unintentional side-effects when updating.  Use ``web.security<2.2`` to get all bugfixes for the current
release, and ``web.security<3.0`` to get bugfixes and feature updates while ensuring that large breaking
changes are not installed.


Development Version
-------------------

    |developstatus| |developcover| |ghsince| |issuecount| |ghfork|

Development takes place on `GitHub <https://github.com/>`__ in the 
`web.security <https://github.com/marrow/web.security/>`__ project.  Issue tracking, documentation,
and downloads are provided there.

Installing the current development version requires `Git <http://git-scm.com/>`_, a distributed source code management
system.  If you have Git you can run the following to download and *link* the development version into your Python
runtime::

    git clone https://github.com/marrow/web.security.git
    pip install -e web.security

You can then upgrade to the latest version at any time::

    cd web.security
    git pull
    pip install -U -e .

If you would like to make changes and contribute them back to the project, fork the GitHub project, make your changes,
and submit a pull request.  This process is beyond the scope of this documentation; for more information see
`GitHub's documentation <http://help.github.com/>`_.











Version History
===============

Version 2.0
-----------

* Reintroduction of WebCore 1 basic account authentication interface.
* Extract of the ACL mechanism from WebCore 2, itself an updated version of the WebCore 1 authorization interface.
* Introduction of new Permission context addition.
* Addition of OWASP Encrypted Token pattern-modeled cross-site request forgery (CSRF) protection.

Version 1.x
-----------

* Process fully integrated in the WebCore web framework as a mixture of components.


License
=======

web.security has been released under the MIT Open Source license.

The MIT License
---------------

Copyright © 2009-2016 Alice Bevan-McGregor and contributors.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the “Software”), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


.. |ghwatch| image:: https://img.shields.io/github/watchers/marrow/web.security.svg?style=social&label=Watch
    :target: https://github.com/marrow/web.security/subscription
    :alt: Subscribe to project activity on Github.

.. |ghstar| image:: https://img.shields.io/github/stars/marrow/web.security.svg?style=social&label=Star
    :target: https://github.com/marrow/web.security/subscription
    :alt: Star this project on Github.

.. |ghfork| image:: https://img.shields.io/github/forks/marrow/web.security.svg?style=social&label=Fork
    :target: https://github.com/marrow/web.security/fork
    :alt: Fork this project on Github.

.. |masterstatus| image:: http://img.shields.io/travis/marrow/web.security/master.svg?style=flat
    :target: https://travis-ci.org/marrow/web.security/branches
    :alt: Release build status.

.. |mastercover| image:: http://img.shields.io/codecov/c/github/marrow/web.security/master.svg?style=flat
    :target: https://codecov.io/github/marrow/web.security?branch=master
    :alt: Release test coverage.

.. |masterreq| image:: https://img.shields.io/requires/github/marrow/web.security.svg
    :target: https://requires.io/github/marrow/web.security/requirements/?branch=master
    :alt: Status of release dependencies.

.. |developstatus| image:: http://img.shields.io/travis/marrow/web.security/develop.svg?style=flat
    :target: https://travis-ci.org/marrow/web.security/branches
    :alt: Development build status.

.. |developcover| image:: http://img.shields.io/codecov/c/github/marrow/web.security/develop.svg?style=flat
    :target: https://codecov.io/github/marrow/web.security?branch=develop
    :alt: Development test coverage.

.. |developreq| image:: https://img.shields.io/requires/github/marrow/web.security.svg
    :target: https://requires.io/github/marrow/web.security/requirements/?branch=develop
    :alt: Status of development dependencies.

.. |issuecount| image:: http://img.shields.io/github/issues-raw/marrow/web.security.svg?style=flat
    :target: https://github.com/marrow/web.security/issues
    :alt: Github Issues

.. |ghsince| image:: https://img.shields.io/github/commits-since/marrow/web.security/2.1.0.svg
    :target: https://github.com/marrow/web.security/commits/develop
    :alt: Changes since last release.

.. |ghtag| image:: https://img.shields.io/github/tag/marrow/web.security.svg
    :target: https://github.com/marrow/web.security/tree/2.1.0
    :alt: Latest Github tagged release.

.. |latestversion| image:: http://img.shields.io/pypi/v/web.security.svg?style=flat
    :target: https://pypi.python.org/pypi/web.security
    :alt: Latest released version.

.. |cake| image:: http://img.shields.io/badge/cake-lie-1b87fb.svg?style=flat
