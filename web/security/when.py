"""Plugin manager and decorator for accessing predicates and defining access control lists."""

from marrow.package.host import PluginManager


class _When(PluginManager):
	"""A derivative of a PluginManager that acts as a decorator.
	
	Will assign the `__acl__` property as the tuple of arguments passed.
	"""
	
	def __call__(self, *acl, **kw):
		inherit = kw.pop('inherit', True)  # Python 2 doesn't support keyword-only arguments.
		
		if __debug__:
			if kw:  # This is the only keyword argument we accept.
				raise TypeError("Unknown keyword arguments: " + ", ".join(sorted(kw)))
		
		def acl_when_inner(target):
			if acl:
				target.__acl__ = acl
			
			if not inherit:
				target.__acl_inherit__ = False
			
			return target
		
		return acl_when_inner

when = _When('web.security.predicate')  # Easy reference by short name, e.g. when.match(...)
