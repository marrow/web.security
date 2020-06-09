"""Web Application Firewall extension for the WebCore web framework.

See also:

* https://en.wikipedia.org/wiki/Web_application_firewall
* https://owasp.org/www-community/Web_Application_Firewall
* https://owasp.org/www-project-little-web-application-firewall/
* https://www.owasp.org/index.php?title=Web_Application_Firewall
* https://www.owasp.org/images/0/0a/Appseceu09-Web_Application_Firewalls.pdf
* https://www.cloudflare.com/en-ca/waf/
"""

from re import compile as re

from typeguard import check_argument_types
from uri import URI

from ...core.typing import Any, Dict, Union, Callable, Path, Set, Pattern, Iterable, MutableSet
from ...core.typing import Context, WSGI, WSGIEnvironment, WSGIStartResponse, Request, Response, Tags
from ...core.context import Context
from ..security.waf import WAFHeuristic


class WebApplicationFirewallExtension:
	"""A basic rules-based Web Application Firewall implementation.
	
	WIP.
	"""
	
	provides:Tags = {'waf'}  # A set of keywords usable in `uses` and `needs` declarations.
	first:bool = True  # Always try to be first: if truthy, become a dependency for all non-first extensions.
	before:Tags = {'debugger', 'request'}  # This extension /really/ means to be first.
	extensions:Tags = {'waf.rule'}  # A set of entry_point namespaces to search for related plugin registrations.
	
	heuristics:Iterable[WAFHeuristic]  # The prepared heuristic instances.
	blacklist:MutableSet[str]  # The current blacklist. Can theoretically be swapped for any mutable set-like object.
	
	def __init__(self, *heuristics:Iterable[WAFHeuristic], **config) -> None:
		"""Executed to configure the extension.
		
		No actions must be performed here, only configuration management.
		
		You can also update the class attributes here. It only really makes sense to manage conditional dependencies.
		"""
		
		assert check_argument_types()
		
		super().__init__()
		
		self.heuristics = heuristics
		self.blacklist = set()
	
	def __call__(self, context:Context, app:WSGI) -> WSGI:
		"""Wrap the WSGI application callable in our 'web application firewall'."""
		
		assert check_argument_types()
		
		def inner(environ:WSGIEnvironment, start_response:WSGIStartResponse):
			# Identify the remote user.
			
			request: Request = Request(environ)
			uri: URI = URI(environ.url)

			# https://docs.pylonsproject.org/projects/webob/en/stable/api/request.html#webob.request.BaseRequest.client_addr
			# Ref: https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
			client: str = request.client_addr
			
			try:
				# Immediately reject known bad actors.
				if request.client_addr in self.blacklist:
					raise HTTPClose()
				
				# Validate the heuristic rules.
				for heuristic in self.heuristics:
					heuristic(environ, uri)
				
				# Finally invoke the wrapped application if everything seems OK.  Note that this pattern of wrapping
				# permits your application to raise HTTPClose if wishing to blacklist the active connection.
				return app(environ, start_response)
			
			except HTTPClose as e:
				self.blacklist.add(request.client_addr)
				return e(environ, start_response)
		
		return inner
	
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

