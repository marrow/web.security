# encoding: utf-8

"""User authentication hooks for WebCore applications.

# Introduction



## Operation



# Usage

## Enabling the Extension


### Imperative Configuration

```python
from web.ext.acl import ACLExtension, when

app = Application("Hi.", extensions=[AuthExtension(...)])
```


### Declarative Configuration

Using a JSON or YAML-based configuration, you would define your application's `extensions` section either with the
bare extension declared:

```yaml
application:
	root: "Hi."
	
	extensions:
		authentication:
			...
```

"""

from __future__ import unicode_literals

from functools import partial

from webob.exc import HTTPTemporaryRedirect
from marrow.package.loader import load

from ..core.compat import unicode, str
from ..core.util import lazy


if __debug__:  # Documentation helpers.
	__doc_groups__ = {  # Map collapsable sections.
				'Imperative Configuration': {'config', 'choice'},
				'Declarative Configuration': {'config', 'choice'},
			}

log = __import__('logging').getLogger(__name__)


class AuthExtension(object):
	"""User authentication extension.
	"""
	
	provides = {'auth', 'authentication'}
	extensions = {'web.auth.lookup', 'web.auth.authenticate'}
	context = {'user'}
	
	def __init__(self, name='user', session='user', intercept={401}, handler='/authenticate', internal=True,
			lookup=None, authenticate=None):
		"""Configure WebCore authentication.
		
		The `name` represents the name of the active user object within the context. The `session` argument represents
		the session attribute to use to store the active user ID after successful authentication. If defined, the set
		of HTTP status code integers to intercept and redirect to the `handler` are passed as `intercept`. If the
		application attempts to return a response matching one of those status codes, the user will instead be directed
		to the authentication handler URL. If `internal` is truthy that redirection will not be visible to the user,
		instead, returning the authentication page as the response body to the intercepted status integer.
		
		The guts of the machinery are the `lookup` and `authenticate` callbacks, which should either be references to
		callables within your code (or library code) or string dot-colon references to the same or a plugin name.
		Reference the module documentation for callback examples.
		
		The `name` provided may be `None`, indicating pure access to the logged in user's identity through the
		session.
		"""
		
		# Authentication data storage configuration.
		self._name = name
		self._session = session
		
		# HTTP status code interception and redirection configuration.
		self._intercept = set(intercept) if intercept else None
		self._handler = handler
		self._internal = internal
		
		# Authentication callback references.
		self._lookup = lookup
		self._authenticate = authenticate
		
		if intercept:
			self.after = self._intercept
		
		log.info("Authentication extension prepared.")
	
	# Application-Level Callbacks
	
	def start(self, context):
		"""Called to load the authentication callbacks and attach them to the context, with glue."""
		
		if isinstance(self._lookup, (str, unicode)):
			self._lookup = load(self._lookup, 'web.auth.lookup')
		
		if isinstance(self._authenticate, (str, unicode)):
			self._authenticate = load(self._authenticate, 'web.auth.authenticate')
		
		if self._name:
			context[self._name] = None
		
		# TODO: context.user = lazy(...)
		context.authenticate = lazy(partial(partial, self.authenticate), 'authenticate')
		context.deauthenticate = lazy(partial(partial, self.deauthenticate), 'deauthenticate')
	
	# Request-Level Callbacks
	
	def _intercept(self, context):
		"""Called after dispatch has returned and the response populated, to intercept and redirect.
		
		Optionally assigned to the correct callback name (`after`) only if interception is enabled.
		"""
		
		if context.response.status_int not in self._intercept:
			return  # Exit early if our condition is not met.
		
		if not self._internal:
			context.response = HTTPTemporaryRedirect(location=self._handler)
			return  # External redirects are easy.
		
		# Internal redirection is a touch more difficult.
		
		request = context.request.copy_get()  # Preserve the user's original request data, such as cookies.
		request.path = self._handler  # Point the internal request at the authentication endpoint.
		request.environ['HTTP_REFERER'] = context.request.path_qs  # Inform authentication where the user was.
		
		response = request.send(context.app)  # Perform the internal redirect.
		response.status_int = context.response.status_int  # Match the status to ensure browser caching not applied.
		context.response = response  # Override the current (failed) response.
	
	# Authentication Extension Callbacks
	
	def authenticate(self, context, identifier, credential=None, force=False):
		"""Authenticate a user.
		
		Sets the current user in the session, if configured to do so. You may omit a cedential and force
		authentication as a given user, if desired.
		
		The context attribute and session attributes, if configured, are updated and available for use immediately
		after the call to this function.  Returns `True` on success, `False` otherwise.
		"""
		
		if force:
			user = self._lookup(identifier) if self._lookup else identifier
		else:
			result = self._authenticate(context, identifier, credential)
		
		if result is None or result[1] is None:
			log.debug("Authentication failed.")
			return False
		else:
			identifier, user = result
		
		log.debug("Authentication successful.")
		
		if self._session:
			self.__write(context.session, self._session, identifier)
		
		return True
	
	def deauthenticate(self, context, nuke=False):
		"""Force logout.
		
		The context variable for the user is immediately deleted, and session variable cleared, as configured.
		
		Additionally, this function may also invalidate (clear) the current session, if requested.
		"""
		
		if nuke:
			context.session.invalidate()
		
		if self._session:
			self.__write(context.session, self._session, None)
	
	# Internal Use Utilities
	
	@staticmethod
	def __write(container, target, value):
		while '.' in target:
			segment, _, target = target.partition('.')
			container = getattr(container, segment)
		
		setattr(container, target, value)

