# encoding: utf-8

from __future__ import unicode_literals

import pytest
from webob import Request

from web.core.context import Context

from web.security.predicate import always, never, First, All, Any, ContextMatch

from helper import must_be_called, must_not_be_called


# # Tests


class TestFirstPredicate(object):
	def test_first_nop(self):
		with must_be_called(3) as nop:
			assert First(nop, nop, nop)('fnord') is None
	
	def test_first_truthy(self):
		assert First(always, always, always)() is True
		
		with must_be_called(2) as nop:
			assert First(nop, nop, always)() is True
		
		with must_not_be_called() as canary:
			assert First(always, canary, canary)() is True
	
	def test_first_falsy(self):
		assert First(never, never, never)() is False
		
		with must_be_called(2) as nop:
			assert First(nop, nop, never)() is False
		
		with must_not_be_called() as canary:
			assert First(never, canary, canary)() is False


class TestAllPredicate(object):
	def test_all_nop(self):
		with must_be_called(3) as nop:
			assert All(nop, nop, nop)('fnord') is None
	
	def test_all_truthy(self):
		assert All(always, always, always)() is True
		
		with must_be_called(2) as nop:
			assert All(always, nop, nop)() is True
	
	def test_all_falsy(self):
		assert All(always, never, always)() is False
		
		with must_not_be_called() as canary:
			assert All(never, canary, canary)() is False
		
		with must_not_be_called() as canary:
			with must_be_called(1) as nop:
				assert All(nop, never, canary)() is False
		
		with must_not_be_called() as canary:
			assert All(always, never, canary)() is False
		
		with must_be_called(2) as nop:
			assert All(nop, nop, never)() is False
		
		with must_not_be_called() as canary:
			assert All(always, never, canary)() is False


class TestAnyPredicate(object):
	def test_any_nop(self):
		with must_be_called(3) as nop:
			assert Any(nop, nop, nop)('fnord') is None
	
	def test_any_truthy(self):
		assert Any(always, always, always)() is True
		
		with must_not_be_called() as canary:
			assert Any(always, canary, canary)() is True
		
		with must_not_be_called() as canary:
			with must_be_called(1) as nop:
				assert Any(nop, always, canary)() is True
	
	def test_any_falsy(self):
		assert Any(never, never, never)() is False
		
		with must_be_called(2) as nop:
			assert Any(never, nop, nop)() is False
		
		with must_be_called(2) as nop:
			assert Any(nop, nop, never)() is False


class TestContextMatchPredicate(object):
	local_request = Request.blank('/', remote_addr='127.0.0.1')
	
	def test_bad_arguments(self):
		with pytest.raises(TypeError):
			ContextMatch(True, 'foo', 27, foo=27)
		
		with pytest.raises(TypeError):
			ContextMatch(True, 'foo')
		
		with pytest.raises(ValueError):
			ContextMatch('foo', 'bar', 27)
		
		with pytest.raises(ValueError):
			ContextMatch(True, 'foo', 27, default='bar')
	
	def test_admin_example_with_no_user(self, admin, context):
		assert admin(context) is None
	
	def test_admin_example_user_with_no_admin_field(self, admin, context):
		context.user = Context()
		assert admin(context) is None
	
	def test_admin_example_user_who_is_not_admin(self, admin, context):
		context.user = Context(admin=False)
		assert admin(context) is None
	
	def test_admin_example_user_who_is_admin(self, admin, context):
		context.user = Context(admin=True)
		assert admin(context) is True


class TestContextContainsPredicate(object):
	def test_reviewer_example_with_no_user(self, reviewer, context):
		assert reviewer(context) is None
	
	def test_reviewer_example_with_no_role_field(self, reviewer, context):
		context.user = Context()
		assert reviewer(context) is None
	
	def test_reviewer_example_without_role(self, reviewer, context):
		context.user = Context(role={'peasant'})
		assert reviewer(context) is None
	
	def test_reviewer_example_with_role(self, reviewer, context):
		context.user = Context(role={'reviewer'})
		assert reviewer(context) is True

