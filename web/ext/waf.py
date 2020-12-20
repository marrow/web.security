"""Web Application Firewall extension for the WebCore web framework.

See also:

* https://en.wikipedia.org/wiki/Web_application_firewall
* https://owasp.org/www-community/Web_Application_Firewall
* https://owasp.org/www-project-little-web-application-firewall/
* https://www.owasp.org/index.php?title=Web_Application_Firewall
* https://www.owasp.org/images/0/0a/Appseceu09-Web_Application_Firewalls.pdf
* https://www.cloudflare.com/en-ca/waf/
"""

from abc import ABCMeta, abstractmethod
from html import escape
from re import compile as re
from socket import inet_aton

from typeguard import check_argument_types
from uri import URI
from webob import Request
from webob.exc import HTTPBadRequest

from web.core.typing import Any, Union, Callable, ClassVar, Generator, Iterable, Optional
from web.core.typing import Dict, Path, Set, Pattern, MutableSet
from web.core.typing import Context, WSGI, WSGIEnvironment, WSGIStartResponse, Request, Response, Tags
from web.core.context import Context
from web.security.waf import WAFHeuristic
from web.security.exc import HTTPClose


log = __import__('logging').getLogger(__name__)  # A standard logger object.


ClientSet = MutableSet[bytes]

class PersistentClientSet(ClientSet, metaclass=ABCMeta):
	"""A mutable set exposing two methods for persisting and restoring its contents."""
	
	@abstractmethod
	def persist(self, context:Context) -> None:
		...
	
	@abstractmethod
	def restore(self, context:Context) -> None:
		...


class WebApplicationFirewallExtension:
	"""A basic rules-based Web Application Firewall implementation."""
	
	provides:ClassVar[Tags] = {'waf'}  # A set of keywords usable in `uses` and `needs` declarations.
	first:ClassVar[bool] = True  # Always try to be first: if truthy, become a dependency for all non-first extensions.
	extensions:ClassVar[Tags] = {'waf.rule'}  # A set of entry_point namespaces to search for related plugin registrations.
	
	uses:ClassVar[Tags] = {'timing.prefix'}  # We want our execution time to be counted.
	
	heuristics:Iterable[WAFHeuristic]  # The prepared heuristic instances.
	blacklist:ClientSet  # The current blacklist. Can theoretically be swapped for any mutable set-like object.
	exempt:ClientSet  # IP addresses exempt from blacklisting.
	
	def __init__(self, *heuristics, blacklist:Optional[ClientSet]=None, exempt:Optional[ClientSet]=None) -> None:
		"""Executed to configure the extension.
		
		No actions must be performed here, only configuration management.
		
		You can also update the class attributes here. It only really makes sense to manage conditional dependencies.
		"""
		
		assert check_argument_types()
		
		super().__init__()
		
		self.heuristics = heuristics
		
		# Permit custom backing stores to be passed in; we optimize by storing packed binary values, not strings.
		self.blacklist = set() if blacklist is None else set(inet_aton(i) for i in blacklist)
		
		# Permit custom backing stores to be passed in for the exemptions, as well.
		self.exempt = set() if exempt is None else exempt
	
	def __call__(self, context:Context, app:WSGI) -> WSGI:
		"""Wrap the WSGI application callable in our 'web application firewall'."""
		
		assert check_argument_types()
		
		def inner(environ:WSGIEnvironment, start_response:WSGIStartResponse):
			try:
				request: Request = Request(environ)  # This will be remembered and re-used as a singleton later.
				uri: URI = URI(request.url)
			
			except Exception as e:  # Protect against de-serialization errors.
				return HTTPBadRequest(f"Encountered error de-serializing the request: {e!r}")(environ, start_response)
			
			# https://docs.pylonsproject.org/projects/webob/en/stable/api/request.html#webob.request.BaseRequest.client_addr
			# Ref: https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
			client: str = request.client_addr
			
			try:
				# Immediately reject known bad actors.
				if inet_aton(request.client_addr) in self.blacklist:
					return HTTPClose()(environ, start_response)  # No need to re-blacklist.
				
				# Validate the heuristic rules.
				for heuristic in self.heuristics:
					try:
						heuristic(environ, uri)
					except HTTPClose as e:
						log.error(f"{heuristic} {e.args[0].lower()}")
						raise
				
				# Invoke the wrapped application if everything seems OK.  Note that this pattern of wrapping permits
				# your application to raise HTTPClose if wishing to blacklist the active connection for any reason.
				return app(environ, start_response)
			
			except HTTPClose as e:
				if request.client_addr not in self.exempt:
					log.warning(f"Blacklisting: {request.client_addr}")
					self.blacklist.add(inet_aton(request.client_addr))
				
				if not __debug__: e = HTTPClose()  # Do not disclose the reason in production environments.
				elif ': ' in e.args[0]:  # XXX: Not currently effective.
					left, _, right = e.args[0].partition(': ')
					e.args = (f"<strong>{left}:</strong> <tt>{escape(right)}</tt>", )
				
				return e(environ, start_response)
		
		return inner
	
	def start(self, context: Context) -> None:
		"""Executed during application startup just after binding the server.
		
		The first argument is the global context class, not request-local context instance.
		
		Any of the actions you wanted to perform during `__init__` you should do here.
		"""
		
		# Permit the storage objects to resume from a saved state.
		if hasattr(self.blacklist, 'restore'): self.blacklist.restore(context)
		if hasattr(self.exempt, 'restore'): self.exempt.restore(context)
	
	def stop(self, context: Context) -> None:
		"""Executed during application shutdown after the last request has been served.
		
		The first argument is the global context class, not request-local context instance.
		"""
		
		# As per startup, permit the storage objects to persist their state.
		if hasattr(self.blacklist, 'persist'): self.blacklist.persist(context)
		if hasattr(self.exempt, 'persist'): self.exempt.persist(context)
	
	def graceful(self, context: Context) -> None:
		"""Called when a SIGHUP is sent to the application.
		
		The first argument is the global context class, not request-local context instance.
		
		Allows your code to re-load configuration and your code should close then re-open sockets and files.
		"""
		
		# Ask the storage object to persist its state, if able.
		if hasattr(self.blacklist, 'persist'): self.blacklist.persist(context)
		if hasattr(self.exempt, 'persist'): self.exempt.persist(context)
	
	def status(self, context: Context) -> Generator[str, None, None]:
		"""Report on the current status of the Web Application Firewall."""
		
		def plural(quantity, single, plural):
			return single if quantity == 1 else plural
		
		c = len(self.heuristics)
		yield f"Rules: {c} {plural(c, 'entry', 'entries')}"
		
		c = len(self.blacklist)
		yield f"Blacklist: {c} {plural(c, 'entry', 'entries')}"
