# encoding: utf-8

from __future__ import unicode_literals

import pytest

from web.security import Predicate
from web.security.predicate import always, never, Not

from helper import must_be_called


class TestBasicPredicateBehaviour(object):
	def test_bare_predicate_fails(self):
		with pytest.raises(NotImplementedError):
			Predicate()()
	
	def test_predicate_partial(self):
		predicate = Not.partial(always)
		assert predicate()() is False
	
	def test_always(self):
		assert always() is True
	
	def test_never(self):
		assert never() is False
	
	def test_not(self):
		assert Not(always)() is False
		assert Not(never)() is True
		
		with must_be_called(1) as nop:
			assert Not(nop)(27) is None

