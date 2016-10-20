# encoding: utf-8

"""A _predicate_ is any callable object that optionally accepts a context as its first positional parameter.

One might look like:

```python
def always(context=None):
	return True
```

That's it, really. The provided built-in ones are class-based, but the process is the same even if the method has a
strange name like `__call__`.

Defining new predicates is fairly straightforward given the very simple interface. However, because many demands of
predicates can be resolved entirely by comparison against a value from the request context, two predicate factories
are provided. These can be used on-demand, or the result can be saved for repeated use later.


## Context Value Matches

Grant or deny access based on a value from the context matching one of several possible values.

```python
deny_console = when.matches(False, 'request.client_addr', None)
local = when.matches(True, 'request.remote_addr', '127.0.0.1', '::1')

@when(deny_console, local, when.matches(True, 'user.admin', True))
def endpoint(context):
	return "Hi."
```

This will grant access to local users and those with the `user.admin` flag equal to `True`, as retrieved from the
context. The `local` predicate has been saved for subsequent use, and demonstrates comparing against any of a number
of allowable values. The first argument is the intended predicate result if a match is made, the second is the value
to traverse and compare, and any remaining arguments are treated as acceptable values.


## Context Value Contains

Grant or deny access based on a value from the context containing one of several possible values.

```python
role = when.contains.partial(True, 'user.role')

@when(role('admin', 'editor'))
def endpoint(context):
	return "Hi."
```

This allows you to easily compare against containers such as lists and sets. Also demonstrataed is the ability to
"partially apply" a predicate, that is, apply some arguments, then apply the rest later.
"""

from __future__ import unicode_literals

from functools import partial

from marrow.package.loader import traverse


if __debug__:  # Documentation helpers.
	__doc_groups__ = {  # Map collapsable sections.
				'Context Value Matches': {'sample', 'captioned'},
				'Context Value Contains': {'sample', 'captioned'},
			}


class Predicate(object):
	__slots__ = ()
	
	def __call__(self, context=None):
		raise NotImplementedError()
	
	@classmethod
	def partial(cls, *args, **kw):
		"""Retrieve a partially applied constructor for this predicate."""
		return partial(cls, *args, **kw)


class Not(Predicate):
	"""Invert the meaning of another predicate."""
	
	__slots__ = ('predicate', )
	
	def __init__(self, predicate):
		self.predicate = predicate
	
	def __call__(self, context=None):
		result = self.predicate(context) if context else self.predicate()
		
		if result is None:
			return
		
		return not result


class Always(Predicate):
	"""Always grant access."""
	
	__slots__ = ()
	
	def __call__(self, context=None):
		return True

always = Always()  # Convienent singleton to use.


class Never(Predicate):
	"""Always deny access."""
	
	__slots__ = ()
	
	def __call__(self, context=None):
		return False

never = Never()  # Convienent singleton to use.


class First(Predicate):
	"""Authorizes or denies an action on the first non-veto predicate."""
	
	__slots__ = ('predicates', )
	
	def __init__(self, *predicates):
		self.predicates = predicates
	
	def __call__(self, context=None):
		for predicate in self.predicates:
			result = predicate(context) if context else predicate()
			
			if result is None:  # Abstain
				continue
			
			return bool(result)


class All(Predicate):
	"""Authorizes an action only if all predicates authorize the action.
	
	Returns `False` on first failure, `True` if all voting predicates returned `True`, `None` otherwise.
	"""
	
	__slots__ = ('predicates', )
	
	def __init__(self, *predicates):
		self.predicates = predicates
	
	def __call__(self, context=None):
		if context:
			results = (predicate(context) for predicate in self.predicates)
		else:
			results = (predicate() for predicate in self.predicates)
		
		vote = None
		
		for result in results:
			if result is None:  # Abstain
				continue
			
			if not bool(result):  # Exit Early
				return False
			
			vote = True
		
		return vote


class Any(Predicate):
	"""Authorize an action if any predicate authorizes the action.
	
	Returns `True` on first success, `False` if all voting predicates returned `False`, `None` otherwise.
	"""
	
	__slots__ = ('predicates', )
	
	def __init__(self, *predicates):
		self.predicates = predicates
	
	def __call__(self, context=None):
		if context:
			results = (predicate(context) for predicate in self.predicates)
		else:
			results = (predicate() for predicate in self.predicates)
		
		vote = None
		
		for result in results:
			if result is None:  # Abstain
				continue
			
			if bool(result):
				return True
			
			vote = False
		
		return vote


class ContextMatch(Predicate):
	"""Match a variable from the context to one of a set of candidate values.
	
	As per most non-base predicates, this accepts a `grant` value determining if a match should be considered success
	(`True`) or not (`False`), then the attribute to attempt to look up, which may be deep or contain array
	references (see the `traverse` function from the `marrow.package.loader` package), and one or more values to
	consider as a match. In the event the attribute can not be loaded, the `default` (which must be passed as a
	keyword argument) will be used, `None` by default.
	
	Examples might include:
	
	admin = ContextMatch(True, 'user.admin', True)
	local = ContextMatch(True, 'request.remote_addr', '127.0.0.1', '::1')
	"""
	
	__slots__ = ('grant', 'attribute', 'values', 'default')
	SENTINEL = object()  # A singleton used internally for comparison.
	
	def __init__(self, grant, attribute, *values, **kw):
		default = kw.pop('default', None)
		
		if __debug__:
			if kw:  # This is the only keyword argument we accept.
				raise TypeError("Unknown keyword arguments: " + ", ".join(sorted(kw)))
			
			if not values:
				raise TypeError("You must supply one or more values to compare against.")
			
			if grant not in (True, False):
				raise ValueError("The `grant` argument must be `True` (allow) or `False` (deny).")
			
			if default not in (None, True, False):
				raise ValueError("The default may either be `True` (allow), `False` (deny), or `None` (abstain).")
		
		self.grant = grant  # True if we grant access, False if we deny access.
		self.attribute = attribute  # The attribute to retrieve, i.e. "user.admin"
		self.values = values
		self.default = default
	
	def __call__(self, context):
		value = traverse(context, self.attribute, self.SENTINEL)  # Retrieve the value.
		
		if value is self.SENTINEL:
			return self.default
		
		result = any(i == value for i in self.values)  # We do this rather than "in" to support equality comparison.
		
		return self.grant if result else None


class ContextContains(ContextMatch):
	"""Match a variable from the context containing one or more values.
	
	Similar to ContextMatch, except matches the values being "in" the target variable rather than comparing equality.
	
	Examples might include:
	
	reviewer = ContextContains(True, 'user.role', 'reviewer')
	"""
	
	__slots__ = ('grant', 'attribute', 'values', 'default')
	
	def __call__(self, context):
		value = traverse(context, self.attribute, self.SENTINEL)  # Retrieve the value.
		
		if value is self.SENTINEL:
			return self.default
		
		result = any(i in value for i in self.values)
		
		return self.grant if result else None

