"""Web Application Firewall extension support for the WebCore web framework."""

from re import compile as re

from typeguard import check_argument_types
from uri import URI

from ...core.typing import Any, Dict, Union, Callable, Path, Set, Pattern, Iterable, Optional
from ...core.typing import WSGIEnvironment
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
		...


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
	
	def __init__(self, *patterns:Iterable[Union[str,Pattern]], *, sensitive=True):
		assert check_argument_types()
		
		self.forbidden = set(str(i) for i in patterns if not isinstance(i, Pattern))
		patterns = set(patterns) - self.forbidden
		
		if patterns:  # For efficiency, we only want one regex. Even better is to avoid them.
			# Construct a suitable singular regular expression from multiple expression fragments.
			self.pattern = re(f'({")|(".join(i.pattern for i in patterns)})')
		
		self.sensitive = sensitive
	
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
