# encoding: utf-8

from __future__ import unicode_literals

import pytest
from webob import Request

from web.core.application import Application
from web.ext.serialize import SerializationExtension

from web.ext.acl import ACLExtension

from web.security.predicate import always, never

from helper import MockController, Grant, EarlyGrant, EarlyDeny, Nuke


class TestExtensionBehaviour(object):
	def do(self, controller, path='/test', **config):
		app = Application(controller, extensions=[ACLExtension(**config), SerializationExtension()])
		req = Request.blank(path)
		resp = req.get_response(app)
		return resp.json if resp.status_int == 200 and resp.body else resp.status_int
	
	def test_unknown_kwarg(self):
		with pytest.raises(TypeError):
			ACLExtension(foo=27)
	
	def test_chained_policy(self):
		ext = ACLExtension(always, policy=[never])
		assert ext.policy[0] is always
		assert ext.policy[1] is never
	
	def test_defaults(self):
		assert self.do(MockController) == 200
		assert self.do(Grant) == 200
		assert self.do(EarlyGrant) == 200
		assert self.do(EarlyDeny) == 403
	
	def test_existing_policy(self):
		assert self.do(MockController, policy=[always]) == 200
		assert self.do(Grant, policy=[always]) == 200
		assert self.do(EarlyGrant, policy=[always]) == 200
		assert self.do(EarlyDeny, policy=[always]) == 403
	
	def test_default_policy(self):
		assert self.do(MockController, default=never) == 403
		assert self.do(Grant, default=never) == 200
		assert self.do(EarlyGrant, default=never) == 200
		assert self.do(EarlyDeny, default=never) == 403
	
	def test_empty_policy(self):
		assert Nuke.test.__acl_inherit__ is False
		assert self.do(Nuke) == 200
	
	def test_return_value_success(self):
		assert self.do(MockController, '/allowed') == {'value': 27}
	
	def test_return_value_failure(self):
		assert self.do(MockController, '/forbidden') == 403

