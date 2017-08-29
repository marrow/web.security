# encoding: utf-8

"""Cross-Site Request Forgery (CSRF) Extension

Provide a session-backed or cryptographic token to secure forms from malicious access.

* This extension is **available in**: `web.security>=2.1.0,<2.2.0`
* This extension has **no external package dependencies**.
* This extension is **available with the name** `csrf` in the `web.ext` namespace.
* This extension adds the following **context attributes**:
	* `csrf`

1. [**Introduction**](#introduction)
	2. [Operation](#operation)
	3. [Predicates](#predicates)
2. [**Usage**](#usage)
	1. [Enabling the Extension](#enabling-the-extension)
		1. [_Imperative Configuration_](#imperative-configuration)
		2. [_Declarative Configuration_](#declarative-configuration)


# Introduction



## Operation



# Usage

## Enabling the Extension

Before utilizing CSRF protection functionality in your own application you must first enable the extension.


### Imperative Configuration

Applications using code to explicitly construct the WebCore `Application` object, but with no particular custom base
ruleset needed, can pass the extension by name. It will be loaded using its `entry_points` plugin reference.

```python
app = Application("Hi.", extensions=['csrf'])
```

To configure, import the extension yourself and specify through initialization.

```python
from web.ext.csrf import CSRFExtension

app = Application("Hi.", extensions=[CSRFExtension(...)])
```

More complex arrangements can be had by specifying rules positionally (their order will be preserved) or by passing a
`policy` iterable by name. These may be combined with the `default` named argument, with them being combined as
`positional` + `policy` + `default`.


### Declarative Configuration

Using a JSON or YAML-based configuration, you would define your application's `extensions` section either with the
bare extension declared:

```yaml
application:
	root: "Hi."
	
	extensions:
		csrf:
```

Or, specify a configuration by treating the `csrf` entry as a mapping:

```yaml
application:
	root: "Hi."
	
	extensions:
		csrf:
			option: value
```
"""

from __future__ import unicode_literals

from weakref import proxy
from functools import partial
from hashlib import sha256
from hmac import new as hmac

from webob.exc import HTTPBadRequest

from ..core.util import safe_name, lazy
from ..core.compat import py3


if __debug__:  # Documentation helpers.
	__doc_groups__ = {  # Map collapsable sections.
				'Imperative Configuration': {'config', 'choice'},
				'Declarative Configuration': {'config', 'choice'},
			}

log = __import__('logging').getLogger(__name__)


class CSRF(object):
	"""Cross-site request forgery protections implementation.
	
	This provides an object meant to be used as a context attribute in association with the `CSRFExtension`.
	
	You can:
	
	* Treat it as a boolean, for example, through casting with `bool()` or by direct use in a boolean expression.
	  This will return `True` if the current request has passed CSRF validation (or is exempt), `False` otherwise.
	
	* Execute it, passing in a token, to validate that token and mark the current request based on the result of that
	  validation.
	
	* Execute it without a token to generate and return a new token based on the current request.
	
	* Use it in templates easily, as you can cast it to a string to generate a new token. An example using common
	  syntax: `${context.csrf}`
	
	* 
	"""
	
	__slots__ = ('_csrf', '_ctx', 'exempt', 'verified', 'replay')
	
	def __init__(self, extension, context):
		"""Construct a new CSRF protections instance.
		
		Most of the configuration is provided though the CSRFExtension instance passed in as `extension`. As CSRF
		tokens involve aspects of the request, such as the referrer and current path, a WebCore context must be
		provided.
		
		"""
		self._csrf = extension
		self._ctx = proxy(context)
		self.exempt = False
		self.verified = False
	
	def __call__(self, token=None):
		"""Generate a token for use in a form, or validate the passed in token."""
		
		if token:
			return self.validate(token)
		
		if self._csrf.session:
			self.seed(False)
		
		if self._csrf.key:
			return self._new_cryptographic()
		
		return self._new_session()
	
	__unicode__ = __call__  # Generate a token if used as a string.
	if py3: __str__ = __unicode__  # Adapt to Python 3 semantics.
	
	def __nonzero__(self):
		"""Permit simple boolean evaluation of the `context.csrf` value to determine validation state."""
		return self.verified
	
	__bool__ = __nonzero__  # Adapt to Python 3 semantics.
	
	def seed(self, force=True):
		"""Generate new session data."""
		
		current = None if force else getattr(self._ctx.session, self._csrf.session, None)
		
		if not current:
			with open('/dev/random', 'rb') as random:
				current = random.read(64)
			
			setattr(self._ctx.session, current)
		
		return current
	
	def validate(self, token):
		"""Identify if a token is valid or not.
		
		Tokens 
		"""
		
		if self.exempt or self.verified:
			return True
		
		c = self._csrf
		
		# TODO: Actually verify.
		
		parts = token.split('g')
		
		if c.lifespan:
			time = None
		
		canon = [
				self._ctx.request.referer,
			]
		
		if self._csrf.lifespan:
			canon.append()
		
		self.verified = True
		return True
	
	def _new_cryptographic(self):
		pass
	
	def _new_session(self):
		pass


class CSRFExtension(object):
	"""Cross-site request forgery (CSRF) protection extension.
	"""
	
	__slots__ = ('needs', 'session', 'key', 'lifespan', 'argument', 'mask', 'required', 'mutate')
	
	provides = {'csrf'}
	context = {'csrf'}
	
	def __init__(self, session='csrf', key=None, lifespan=None, xhr=True, argument=None, mask=True, required=False, replay=False, scale=True):
		"""Configure the CSRF extension.
		
		Define the attribute used to store the random CSRF value (or per-session key) by passing in a `session` value.
		If this value is falsy the session will not be utilized for storage. The default is `csrf`.
		
		Cryptographic verification via HMAC may be enabled by specifying a `key` string to use for protection. This
		type of use does not require the use of sessions at all. Alternatively, random per-session keys may be used by
		combining a `session` with `key` of `True`. Keys should be 64 bytes in length.
		
		If a lifespan is defined a timestamp will be included in the CSRF token and checked to ensure its maximum age
		is no greater than `lifespan` in minutes or as represented by a `timedelta`. This requires cryptographic
		verification be enabled.
		
		XHR requests are exempted by default, since the XHR header is protected by CORS headers. Please see the
		`CORSExtension` for easily configuring those security settings. If you wish to disable this behavour, pass a
		falsy value as `xhr`.
		
		If you wish this extension to automatically validate a specific named argument on any invocation providing it,
		specify the name as `argument`. When enabled this way this argument is automatically removed so as to not
		clutter endpoint argument specifications. You can prevent this by specifying a falsy `mask`. If `required` is
		truthy then this argument will be required in any request containing keyword arguments not otherwise exempted,
		and the request will be rejected with an HTTP "400 Bad Request".
		
		The argument `replay` denotes if replay protections should be enabled or not, and what the size of the
		replay buffer should be. If `scale` is truthy than this number represents the maximum size. Tokens may only
		be verified **once** if replay protection is enabled.
		"""
		
		self.needs = {}
		
		if session:  # Update our extension's dependencies if session interaction is indicated.
			self.needs.add('session')
		
		if argument:
			self.needs.add('kwargs')
		
		if key and hasattr(key, 'encode'):  # Keys must be binary.
			key = key.encode('utf-8')
		
		try:  # Convert to seconds.
			lifespan = lifespan.total_seconds()
		except AttributeError:
			lifespan = int(lifespan * 60)
		
		self.session = session
		self.key = key
		self.lifespan = lifespan
		self.argument = argument
		self.mask = mask
		self.required = required
		
		if argument:
			self.mutate = self._handle_argument
		
		if __debug__:
			if len(key) != 64:
				log.warn("It's recommended for signing keys to be exactly 64 bytes in length.")
	
	# ### Request-Level Callbacks
	
	def start(self, context):
		"""Called to prepare the context by adding a `csrf` attribute."""
		
		context.csrf = lazy(partial(CSRF, self), 'csrf')  # Will be called on access to bind to the context.
	
	def _handle_argument(self, context, handler, bound, args, kw):
		if any(getattr(crumb.handler, '__csrf__', True) is False for crumb in context.path):
			context.csrf.exempt = True
			return  # Exemption equates to "always verified".
		
		if not kw:
			return  # No data? Not verified.
		
		if self.argument not in kw:
			if self.required:
				log.error("Request did not contain required CSRF token.")
				raise HTTPBadRequest()
			
			return  # No token?  Not verified.
		
		token = kw.pop(self.argument)
		
		if not context.csrf(token):
			log.error("Request contained invalid CSRF token.")
			raise HTTPBadRequest()
		
		if not self.mask:
			kw[self.argument] = context.csrf

