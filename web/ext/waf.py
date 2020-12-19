"""Web Application Firewall extension for the WebCore web framework.

See also:

* https://en.wikipedia.org/wiki/Web_application_firewall
* https://owasp.org/www-community/Web_Application_Firewall
* https://owasp.org/www-project-little-web-application-firewall/
* https://www.owasp.org/index.php?title=Web_Application_Firewall
* https://www.owasp.org/images/0/0a/Appseceu09-Web_Application_Firewalls.pdf
* https://www.cloudflare.com/en-ca/waf/
"""

from html import escape
from re import compile as re

from typeguard import check_argument_types
from uri import URI

from web.core.typing import Any, Dict, Union, Callable, ClassVar, Path, Set, Pattern, Iterable, MutableSet, Optional
from web.core.typing import Context, WSGI, WSGIEnvironment, WSGIStartResponse, Request, Response, Tags
from web.core.context import Context
from web.security.waf import WAFHeuristic
from web.security.exc import HTTPClose


log = __import__('logging').getLogger(__name__)  # A standard logger object.


ClientSet = MutableSet[str]


class WebApplicationFirewallExtension:
	"""A basic rules-based Web Application Firewall implementation.
	
	WIP.
	"""
	
	provides:ClassVar[Tags] = {'waf'}  # A set of keywords usable in `uses` and `needs` declarations.
	first:ClassVar[bool] = True  # Always try to be first: if truthy, become a dependency for all non-first extensions.
	extensions:ClassVar[Tags] = {'waf.rule'}  # A set of entry_point namespaces to search for related plugin registrations.
	
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
		self.blacklist = set() if blacklist is None else blacklist  # Permit custom backing stores to be passed in.
		self.exempt = set() if exempt is None else exempt  # Permit custom backing stores to be passed in.
	
	def __call__(self, context:Context, app:WSGI) -> WSGI:
		"""Wrap the WSGI application callable in our 'web application firewall'."""
		
		assert check_argument_types()
		
		def inner(environ:WSGIEnvironment, start_response:WSGIStartResponse):
			# Identify the remote user.
			
			request: Request = Request(environ)
			uri: URI = URI(request.url)
			
			# https://docs.pylonsproject.org/projects/webob/en/stable/api/request.html#webob.request.BaseRequest.client_addr
			# Ref: https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
			client: str = request.client_addr
			
			try:
				# Immediately reject known bad actors.
				if request.client_addr in self.blacklist:
					return HTTPClose()(environ, start_response)  # No need to re-blacklist.
				
				# Validate the heuristic rules.
				for heuristic in self.heuristics:
					try:
						heuristic(environ, uri)
					except HTTPClose as e:
						log.error(f"{heuristic} {e.args[0].lower()}")
						raise
				
				# Invoke the wrapped application if everything seems OK.  Note that this pattern of wrapping permits
				# your application to raise HTTPClose if wishing to blacklist the active connection.
				return app(environ, start_response)
			
			except HTTPClose as e:
				if request.client_addr not in self.exempt:
					log.warning(f"Blacklisting: {request.client_addr}")
					self.blacklist.add(request.client_addr)
				
				if not __debug__: e = HTTPClose()  # Do not disclose the reason in production environments.
				elif ': ' in e.args[0]:  # XXX: Not currently effective.
					left, _, right = e.args[0].partition(': ')
					e.args = (f"<strong>{left}:</strong> <tt>{escape(right)}</tt>", )
				
				return e(environ, start_response)
		
		return inner
	
	def prepare(self, context: Context) -> None:
		"""Armor the base extension against maliciously formed requests."""
		
		try:
			Request(context.environ)  # Requests are singletons, so BaseExtension later won't do more work.
		except Exception as e:
			raise HTTPClose(f"Encountered error de-serializing the request: {e!r}")
	
	def start(self, context: Context) -> None:
		"""Executed during application startup just after binding the server.
		
		The first argument is the global context class, not request-local context instance.
		
		Any of the actions you wanted to perform during `__init__` you should do here.
		"""
		...
	
	def stop(self, context: Context) -> None:
		"""Executed during application shutdown after the last request has been served.
		
		The first argument is the global context class, not request-local context instance.
		"""
		...
	
	def graceful(self, context: Context, **config) -> None:
		"""Called when a SIGHUP is sent to the application.
		
		The first argument is the global context class, not request-local context instance.
		
		Allows your code to re-load configuration and your code should close then re-open sockets and files.
		"""
		...
	
	def status(self, context: Context) -> None:
		"""Report on the current status of the Web Application Firewall."""
		
		def plural(quantity, single, plural):
			return single if quantity == 1 else plural
		
		c = len(self.heuristics)
		yield f"**Rules:** {c} {plural(c, 'entry', 'entries')}"
		
		c = len(self.blacklist)
		yield f"**Blacklist:** {c} {plural(c, 'entry', 'entries')}"
