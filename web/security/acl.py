# encoding: utf-8

"""ACL evaluation result and ACL abstractions."""

from __future__ import unicode_literals

from weakref import proxy
from itertools import chain


log = __import__('logging').getLogger(__name__)


class ACLResult(object):
	__slots__ = ('result', 'predicate', 'path', 'source')
	
	def __init__(self, result, predicate, path=None, source=None):
		self.result = result
		self.predicate = predicate
		self.path = path
		self.source = source
	
	def __bool__(self):
		return bool(self.result)
	
	__nonzero__ = __bool__


class ACL(list):
	def __init__(self, *rules, **kw): # Python 3: , context=None, policy=None):
		super(ACL, self).__init__((None, rule, None) for rule in rules)
		
		context = kw.pop('context', None)
		policy = kw.pop('policy', None)
		
		if __debug__:
			if kw:  # This is the only keyword argument we accept.
				raise TypeError("Unknown keyword arguments: " + ", ".join(sorted(kw)))
		
		self.context = proxy(context) if context else None
		self.policy = policy or ()
	
	@property
	def is_authorized(self):
		for path, predicate, source in self:
			result = predicate() if self.context is None else predicate(self.context)
			
			if __debug__:
				log.debug(repr(predicate) + " (from " + repr(source) + ") voted " + repr(result))
			
			if result is None:
				continue
			
			return ACLResult(result, predicate, path, source)
		
		return ACLResult(None, None, None, None)
	
	def __bool__(self):
		return bool(len(self) or len(self.policy))
	
	__nonzero__ = __bool__
	
	def __iter__(self):
		return chain(super(ACL, self).__iter__(), ((None, i, None) for i in self.policy))
	
	def __repr__(self):
		return '[' + ', '.join(repr(i) for i in self) + ']'

