# encoding: utf-8

from __future__ import unicode_literals

from contextlib import contextmanager

from web.security import when
from web.security.predicate import always, never


@contextmanager
def must_be_called(n=None):
	"""Ensure the target function is called.
	
	If an `n` value is supplied, ensure the target is called that many times.
	"""
	called = []
	
	def must_call(context=None):
		called.append(context)
	
	yield must_call
	
	if n is None:
		assert len(called) > 0, "Predicate that must be called, was not."
	
	else:
		assert len(called) == n, "Predicate that must be called " + str(n) + " times was called " + \
				str(len(called)) + " times."


@contextmanager
def must_not_be_called():
	"""Ensure the target function is never called."""
	called = []
	
	def must_not_call(context=None):
		called.append(context)
	
	yield must_not_call
	
	assert len(called) == 0, "Predicate that must not be called, was."


class MockController:
	def __init__(self, context):
		self._ctx = context
	
	def test(self):
		return None
	
	def allowed(self):
		class secret(dict):
			__acl__ = [always]
		return secret(value=27)
	
	def forbidden(self):
		class secret(dict):
			__acl__ = [never]
		return secret(value=27)


@when(always)
class Grant(MockController):
	pass


@when(always)
class EarlyGrant(MockController):
	@when(never)
	def test(self):
		return None


@when(never)
class EarlyDeny(MockController):
	@when(always)
	def test(self):
		return None


@when(never)
class Nuke(MockController):
	@when(inherit=False)
	def test(self):
		return None

