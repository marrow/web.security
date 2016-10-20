# encoding: utf-8

"""Tag-based permission or role-based authroization support."""

from weakref import proxy


class PermissionSource:
	"""A method to retrieve valid permissions for a given user."""
	
	def __init__(self):
		pass
	
	def __call__(self, context):
		pass


class Permissions:
	"""A class to lazily evaluate a user's permissions.
	
	You can, after construction, perform `in` queries such as:
	
		if 'admin' in context.permissions: ...
	
	Useful in concert with the `when.contains` predicate:
	
		has = when.contains.partial(True, 'permissions')
		has('admin')
	
	May be added to, extended, or updated, but only reads trigger collection from configured `PermissionSource`
	instances:
	
		context.permissions.add('potato')
	
	Removal via `remove` requires population, `clear` does not.  You can also easily iterate the available flags, for
	example to by passing to `list`, `set`, or `tuple`. Permissions are iterated in sorted order. No manipulation
	method will raise an exception, and each returns `self` to allow method chaining.
	"""
	
	def __init__(self, context, *sources):
		self.sources = sources
		self.context = proxy(context)
		self.permissions = set()
		self.unpacked = False
	
	def _unpack(self):
		self.clear()
		self.update(*(source(self.context) for source in self.sources))
	
	def add(self, *values):
		"""Add one or more permissions to the set.
		
		Always returns self (to allow chaining), never explodes.
		"""
		self.permissions.extend(values)
		return self
	
	def remove(self, *values):
		"""Remove one or more permissions from the set.
		
		Always returns self (to allow chaining), never explodes.
		"""
		if not self.unpacked: self._unpack()
		map(self.permissions.discard, values)
		return self
	
	def extend(self, *values):
		"""Extend the set of permissions with one or more iterable.
		
		Always returns self (to allow chaining), never explodes.
		"""
		map(self.permissions.extend, values)
		return self
	
	update = extend
	
	def reset(self):
		"""Clear and ensure permission sources are re-evaluated.
		
		Always returns self (to allow chaining), never explodes.
		"""
		self.permissions = set()
		self.unpacked = False
		return self
	
	def clear(self):
		"""Clear all permissions and ensure permission sources are not re-evaluated.
		
		Always returns self (to allow chaining), never explodes.
		"""
		self.permissions = set()
		self.unpacked = True
		return self
	
	def __contains__(self, value):
		if not self.unpacked: self._unpack()
		return value in self.permissions
	
	def __iter__(self):
		if not self.unpacked: self._unpack()
		return iter(sorted(self.permissions))

