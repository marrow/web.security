#!/usr/bin/env python3

from setuptools import setup
from sys import argv, version_info as python_version
from pathlib import Path


if python_version < (3, 6):
	raise SystemExit("Python 3.6 or later is required.")

here = Path(__file__).resolve().parent
version = description = url = author = None  # Populated by the next line.
exec((here / "web" / "security" / "release.py").read_text('utf-8'))

tests_require = [
		'pytest',  # test collector and extensible runner
		'pytest-cov',  # coverage reporting
		'pytest-flakes',  # syntax validation
		'pytest-isort',  # import ordering
		'WebCore',  # request mocking
		'web.dispatch.object',  # endpoint discovery
	]


setup(
	name = "web.security",
	version = version,
	
	description = description,
	long_description = (here / 'README.rst').read_text('utf-8'),
	url = url,
	download_url = 'https://github.com/marrow/web.security/releases',
	
	author = author.name,
	author_email = author.email,

	license = 'MIT',
	keywords = [
			'web.security',
			'WebCore',
			'ACL',
			'CSRF',
			'CORS',
			'authentication',
			'authorization',
			'authn',
			'authz',
			'a12n',
			'a11n'
		],
	classifiers = [
			"Development Status :: 5 - Production/Stable",
			"Environment :: Console",
			"Environment :: Web Environment",
			"Intended Audience :: Developers",
			"License :: OSI Approved :: MIT License",
			"Operating System :: OS Independent",
			"Programming Language :: Python",
			"Programming Language :: Python :: 3",
			"Programming Language :: Python :: 3.6",
			"Programming Language :: Python :: 3.7",
			"Programming Language :: Python :: 3.8",
			"Programming Language :: Python :: Implementation :: CPython",
			"Programming Language :: Python :: Implementation :: PyPy",
			"Topic :: Software Development :: Libraries :: Python Modules",
		],
	
	packages = ('web.ext', 'web.security', 'web.signature'),
	include_package_data = True,
	package_data = {'': ['README.rst', 'LICENSE.txt']},
	zip_safe = False,
	
	setup_requires = [
			'pytest-runner',
		] if {'pytest', 'test', 'ptr'}.intersection(argv) else [],
	
	install_requires = [
			'WebCore~=3.0.0',  # Web framework.
			'marrow.package~=2.0',  # Plugin management.
		],
	
	extras_require = dict(
			development = tests_require + ['pre-commit', 'bandit', 'e', 'pudb', 'ptipython'],
			ecdsa = ['fastecdsa>=1.0.3'],
			fastecdsa = ['fastecdsa>=1.0.3'],  # Deprecated reference.
			geo = ['IP2Location'],
		),
	
	tests_require = tests_require,
	
	entry_points = {
			'web.extension': [
					'acl = web.ext.acl:ACLExtension',  # Access control list validation.
				],
			'web.security.predicate': [
					'not = web.security.predicate:Not',
					'always = web.security.predicate:always',
					'never = web.security.predicate:never',
					'first = web.security.predicate:First',
					'all = web.security.predicate:All',
					'any = web.security.predicate:Any',
					'matches = web.security.predicate:ContextMatch',
					'contains = web.security.predicate:ContextContains',
				],
			'web.security.heuristic': [
					'dns = web.security.waf:ClientDNSHeuristic',
					'path = web.security.waf:PathHeuristic',
					'php = web.security.waf:PHPHeuristic',
					'wordpress = web.security.waf:WordpressHeuristic',
					'hosting = web.security.waf:HostingCombinedHeuristic',
					'country = web.security.waf:GeoCountryHeuristic',
				]
		},
)
