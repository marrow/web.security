"""Release information about the WebCore security framework."""

from collections import namedtuple

version_info = namedtuple('version_info', ('major', 'minor', 'micro', 'releaselevel', 'serial'))(3, 0, 0, 'final', 1)
version = ".".join([str(i) for i in version_info[:3]]) + ((version_info.releaselevel[0] + str(version_info.serial)) if version_info.releaselevel != 'final' else '')

author = namedtuple('Author', ['name', 'email'])("Alice Bevan-McGregor", 'alice@gothcandy.com')
description = "Access control list (ACL) authorization, authentication, and cross-site request forgery (CSRF) protection for WebCore applications."
copyright = "2009-2019, Alice Bevan-McGregor and contributors"
url = 'https://github.com/marrow/web.security'
