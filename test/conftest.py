# encoding: utf-8

from __future__ import unicode_literals

import pytest

from web.core.context import Context

from web.security.predicate import ContextMatch, ContextContains


@pytest.fixture
def context():
	"""Sometimes, you just need an empty context."""
	yield Context()


@pytest.fixture
def admin():
	"""The "administrative user" example for ContextMatch."""
	yield ContextMatch(True, 'user.admin', True)


@pytest.fixture
def reviewer():
	"""The "content reviewer" example for ContextIn."""
	yield ContextContains(True, 'user.role', 'reviewer')

