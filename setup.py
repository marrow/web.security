#!/usr/bin/env python
# encoding: utf-8

from __future__ import print_function

import os
import sys
import codecs


try:
	from setuptools.core import setup, find_packages
except ImportError:
	from setuptools import setup, find_packages


if sys.version_info < (2, 7):
	raise SystemExit("Python 2.7 or later is required.")
elif sys.version_info > (3, 0) and sys.version_info < (3, 2):
	raise SystemExit("Python 3.2 or later is required.")

version = description = url = author = None
exec(open(os.path.join("web", "security", "release.py")).read())

here = os.path.abspath(os.path.dirname(__file__))

tests_require = [
		'pytest',  # test collector and extensible runner
		'pytest-cov',  # coverage reporting
		'pytest-flakes',  # syntax validation
		'pytest-capturelog',  # log capture
		'pytest-spec',  # output formatting
		'WebCore',  # request mocking
	]


setup(
	name = "web.security",
	version = version,
	description = description,
	long_description = codecs.open(os.path.join(here, 'README.rst'), 'r', 'utf8').read(),
	url = url,
	download_url = 'https://github.com/marrow/web.security/releases',
	author = author.name,
	author_email = author.email,
	license = 'MIT',
	keywords = ['web.security', 'WebCore', 'ACL', 'CSRF', 'authentication', 'authorization', 'authn', 'authz', 'a12n', 'a11n'],
	classifiers = [
			"Development Status :: 5 - Production/Stable",
			"Environment :: Console",
			"Environment :: Web Environment",
			"Intended Audience :: Developers",
			"License :: OSI Approved :: MIT License",
			"Operating System :: OS Independent",
			"Programming Language :: Python",
			"Programming Language :: Python :: 2",
			"Programming Language :: Python :: 2.7",
			"Programming Language :: Python :: 3",
			"Programming Language :: Python :: 3.2",
			"Programming Language :: Python :: 3.3",
			"Programming Language :: Python :: 3.4",
			"Programming Language :: Python :: 3.5",
			"Programming Language :: Python :: Implementation :: CPython",
			"Programming Language :: Python :: Implementation :: PyPy",
			"Topic :: Software Development :: Libraries :: Python Modules",
		],
	
	packages = find_packages(exclude=['example', 'test']),
	include_package_data = True,
	namespace_packages = [
			'web',  # primary namespace
			'web.ext',  # framework extensions
		],
	
	entry_points = {
			'web.extension': [
					'acl = web.ext.acl:ACLExtension',  # Access control list validation.
				],
			'web.security.predicate': [
					'not = web.security.predicate:Not',
					'always = web.security.predicate:always',
					'never = web.security.predicate:never',
					'first = web.security.predicate:First',
					'all = web.security.predicate:all',
					'any = web.security.predicate:any',
					'matches = web.security.predicate:ContextMatch',
					'contains = web.security.predicate:ContextContains',
				],
		},
	
	setup_requires = [
			'pytest-runner',
		] if {'pytest', 'test', 'ptr'}.intersection(sys.argv) else [],
	install_requires = [
		],
	
	extras_require = dict(
			development = tests_require,
		),
	
	tests_require = tests_require,
	
	zip_safe = True,
)
