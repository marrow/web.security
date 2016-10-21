# encoding: utf-8

from __future__ import unicode_literals

import pytest

from web.security import ACL, when
from web.security.acl import ACLResult
from web.security.predicate import always

from helper import must_be_called


class TestPredicateHelpers(object):
	def test_when_decorator(self):
		@when(None)
		def inner(): pass
		
		assert inner.__acl__ == (None,)
		
		with pytest.raises(TypeError):
			when(foo=27)
	
	def test_acl_result_behaviour(self):
		assert bool(ACLResult(True, None)) is True
		assert bool(ACLResult(False, None)) is False
		assert bool(ACLResult(None, None)) is False
	
	def test_acl_invalid_construction(self):
		with pytest.raises(TypeError):
			ACL(foo=27)
	
	def test_acl_repr(self):
		acl = ACL(27, policy=(42,))
		assert repr(acl) == '[(None, 27, None), (None, 42, None)]'
	
	def test_acl_skip(self):
		with must_be_called(1) as nop:
			acl = ACL(nop, always)
			assert acl.is_authorized.result is True
	
	def test_acl_fallthrough(self):
		with must_be_called(1) as nop:
			acl = ACL(nop)
			assert acl.is_authorized.result is None

