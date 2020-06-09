"""Web Application Firewall extension support for the WebCore web framework."""

from uri import URI

from ...core.typing import Any, Dict, Union, Callable, Path, Set, Pattern, Iterable, Optional
from ...core.typing import WSGIEnvironment


class WAFHeuristic:
	def __call__(self, environ:WSGIEnvironment, uri:URI) -> Optional[bool]:
		"""Perform the heuristic check.
		
		May return True to indicate processing should stop, raise an HTTPException to propagate to the client, or may
		even do nothing (returning `None` naturally). In "suitable for blacklisting" cases, raise the provided
		`HTTPClose` exception; on compliant HTTP servers, this will immediately terminate the connection and is the
		lowest-overhead option to limit the impact of abuse.
		"""
		...
