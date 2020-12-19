"""Web Application Firewall extension support for the WebCore web framework."""

from logging import getLogger as log
from re import compile as re

from typeguard import check_argument_types
from uri import URI

from web.core.typing import Any, Dict, Union, Callable, Path, Set, Pattern, Iterable, Optional
from web.core.typing import WSGIEnvironment
from .util import DNS
from .exc import HTTPClose


class WAFHeuristic:
	def __call__(self, environ:WSGIEnvironment, uri:URI) -> Optional[bool]:
		"""Perform the heuristic check.
		
		May return True to indicate processing should stop, raise an HTTPException to propagate to the client, or may
		even do nothing (returning `None` naturally). In "suitable for blacklisting" cases, raise the provided
		`HTTPClose` exception; on compliant HTTP servers, this will immediately terminate the connection and is the
		lowest-overhead option to limit the impact of abuse.
		"""
		
		raise NotImplementedError()
	
	def __repr__(self, *extra) -> str:
		"""Programmer's representation."""
		return f"{self.__class__.__module__}.{self.__class__.__qualname__}({', '.join(extra)})"


class ClientDNSHeuristic(WAFHeuristic):
	"""Perform (and optionally require) reverse DNS validation of the incoming client connection, optionally bypassing
	additional heuristic processing (whitelisting) if the reverse DNS domain name is or ends with a given suffix.
	
	If the IP address maps to a DNS name that does not then resolve to a pool of IP addresses including the client's,
	that connection is considered "forged" and is rejected. Resolution failures represent a no-op unless `required` is
	truthy. Patterns may be explicit (e.g. `example.com`), wildcard domain and all subdomains (`.example.com`) or may
	be compiled regular expressions used to match the resolved reverse DNS name.
	
	Validation of reverse DNS is a recommended process for verifying requests originating from Googlebot, ref:
	https://support.google.com/webmasters/answer/80553 - to this end, pass `('.google.com', '.googlebot.com')` as the
	`domains` argument to the constructor.
	
	Due to this being an "expensive" heuristic (in terms of microsecond cost) utilizing a synchronous DNS resolver,
	resolution requests (both forward and reverse) are LRU cached for an hour with a maximum of 128 entries. This
	should adequately handle bursty traffic patterns from small clusters of users without an excessive memory cost.
	"""
	
	__slots__ = ('domains', 'origin', 'required')
	
	domains: Iterable[str]  # An iterable of specific domain names, or dot-prefixed domain suffixes to whitelist.
	origin: str  # The WSGI environment variable to source the requesting client's IP address from.
	required: bool  # Is valid reverse DNS resolution required to permit a connection?
	
	def __init__(self, domains:Iterable[str]=(), origin:str='REMOTE_ADDR', required:bool=False):
		"""Prevent additional heuristic processing if the requesting client's resolved DNS name ends in a given suffix.
		
		May optionally specify the name of a WSGI environment variable or HTTP header to use as an alternate "trusted
		origin" for the client's IP address, useful if utilized behind a reverse proxy, for example.  A common value
		is `X-Forwarded-For`, the default is `REMOTE_ADDR`. If `required`, reverse DNS (and subsequent forward
		validation) must succeed or the client will be rejected, regardless of whitelist presence.
		"""
		
		assert check_argument_types()
		
		self.domains = domains
		self.origin = f'HTTP_{origin.upper().replace('-', '_')}' if '-' in origin else origin.upper()
		self.required = required
		
		self._log = log(f'{__name__}:ClientDNSHeuristic')
	
	def __repr__(self, *extra:str) -> str:
		return super().__repr__(
				f"domains={self.domains!r}",
				f"origin={self.origin!r}",
				f"required={self.required!r}",
				*extra
			)
	
	def __call__(self, environ:WSGIEnvironment, uri:URI) -> Optional[bool]:
		assert check_argument_types()
		
		addr:str = environ.get(self.origin, '')  # Attempt to retrieve the client IP from the WSGI environment.
		
		if not addr:  # Client IP address discovery failed, this is generally not OK.
			self._log.error("Unable to determine requesting client IP address.")
			
			if self.required:  # Explode if required...
				raise HTTPClose("Unable to determine requesting client IP address.")
			
			return  # Otherwise, there's nothing more this heuristic can do.
		
		host:Optional[str] = DNS.reverse(addr)  # Attempt reverse DNS lookup of the client IP address.
		
		if not host:  # Reverse lookup failed, we can't perform the remaining checks, but this can be OK.
			if self.required:
				self._log.critical("Mandatory reverse DNS lookup failed.", extra={'ip': addr})
				raise HTTPClose("Mandatory reverse DNS lookup failed.")
			
			self._log.warn("Reverse DNS lookup failed.", extra={'ip': addr})
			return
		
		# Ensure the IP address forward-resolves for the reverse name given.
		permitted = DNS.forward(host)
		
		if addr not in permitted:
			self._log.critical(f'Connection from {addr}, {permitted!r} permitted for reverse DNS name "{host}".',
					extra={'ip': addr, 'permitted': permitted, 'host': host})
			raise HTTPClose("Spoofed IP address or invalid reverse DNS information, see log for details.")
		
		# Expose our discovered DNS name to the application, to save a second expensive lookup later, if needed.
		environ['REMOTE_HOST'] = host
		
		# Short-circuit processing if requesting from a whitelisted domain.
		for pattern in self.domains:
			if isinstance(pattern, Pattern):
				if pattern.search(dnsname):
					self._log.info(f"Bypassing remaining heuristics, matched regex reverse DNS pattern: {pattern}",
							extra={'ip': addr, 'host': host, 'pattern': pattern})
					return True
			
			elif dnsname == pattern or (pattern[0] == '.' and dnsname == pattern[1:] or dnsname.endswith(pattern)):
				self._log.info(f"Bypassing remaining heuristics, matched reverse DNS pattern: {pattern}",
						extra={'ip': addr, 'host': host, 'pattern': pattern})
				return True
		
		if __debug__:
			self._log.debug("Client IP validated through reverse DNS lookup.")


class PathHeuristic(WAFHeuristic):
	"""Forbid requests whose path contains a given element, or whose path matches one or more regular expressions.
	
	This is a _high efficiency_ heuristic, relying on Python's fast set operators where possible, while also allowing
	regular-expression based whole-path comparisons. Simple example, prevent any request involving a path element
	named `phpMyAdmin`:
	
		PathHeuristic('phpMyAdmin')
	
	One can also deny any request targeting a PHP script:
	
		PathHeuristic(re.compile(r'\.phps?($|/)'))
	
	It's important to note that regular expression flags (such as case insensitivity) will be ignored; the search is
	always case sensitive.  (phpMyAdmin != phpmyadmin; these are legitimately separate resources.)
	"""
	
	forbidden:Set[str]  # A set of path elements whose presence is forbidden.
	pattern:Optional[Pattern] = None  # The compiled singular regular expression for rejection matching.
	sensitive:bool  # Indicating if the comparison is performed case-sensitively or not.
	
	def __init__(self, *patterns:Union[str,Pattern], sensitive:bool=True) -> None:
		assert check_argument_types()
		
		self.forbidden = set(str(i) for i in patterns if not isinstance(i, Pattern))
		patterns = set(patterns) - self.forbidden
		
		if patterns:  # For efficiency, we only want one regex. Even better is to avoid them.
			# Construct a suitable singular regular expression from multiple expression fragments.
			self.pattern = re(f'({")|(".join(i.pattern for i in patterns)})')
		
		self.sensitive = sensitive
	
	def __repr__(self, *extra:str) -> str:
		return super().__repr__(
				f"forbidden={self.forbidden!r}",
				f"pattern={self.pattern.pattern!r}",
				f"sensitive={self.sensitive!r}",
				*extra
			)
	
	def __call__(self, environ:dict, uri:URI) -> None:
		assert check_argument_types()
		
		if self.forbidden & set(uri.path.parts):  # This is ~a third faster than the simplest regex use.
			raise HTTPClose()
		
		if self.pattern and self.pattern.search(str(uri)):  # The slower choice below a complexity threshold.
			raise HTTPClose()


class PHPHeuristic(PathHeuristic):
	"""A variant PathHeuristic looking for any path element with a '.php' or '.phps' filename extension.
	
	This is a Python web application.  Attempts to access any "PHP script" must, by definition, be fraudulent.
	"""
	
	def __init__(self) -> None:
		super().__init__(re(r'\.phps?($|/)'))


class WordpressHeuristic(PathHeuristic):
	"""Beyond attempts to access PHP scripts, more generally we can rapidly block Wordpress requests by string match.
	
	This is more efficient than the global PHPHeuristic and will additionally block any attempt to access _any_
	resource below such a path, not just PHP scripts.
	"""
	
	def __init__(self) -> None:
		super().__init__('wordpress', 'wp', 'wp-admin', 'wp-includes', 'wlwmanifest.xml', 'xmlrpc.php')
