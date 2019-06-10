"""Access Control List Security Extension

Predicate-based security for your applications, extensions, and reusable components.

* This extension is **available in**: `WebCore>=2.0.3,<2.1.0`
* This extension **requires [Python 3](https://www.python.org/)**.
* This extension has **no external package dependencies**.
* This extension is **available with the name** `acl` in the `web.ext` namespace.
* This extension adds the following **context attributes**:
	* `acl`
* This extension uses **namespaced plugins** from:
	* `web.acl.predicate`

1. [**Introduction**](#introduction)
	2. [Operation](#operation)
	3. [Predicates](#predicates)
2. [**Usage**](#usage)
	1. [Enabling the Extension](#enabling-the-extension)
		1. [_Imperative Configuration_](#imperative-configuration)
		2. [_Declarative Configuration_](#declarative-configuration)
	2. [Defining ACLs](#defining-acls)
		1. [_Explicit Usage_](#explicit-usage)
		2. [_Decoration_](#decoration)
		3. [_Endpoint Return Values_](#endpoint-return-values)


# Introduction

This extension provides a method of collecting rules from objects during dispatch descent and subsequently evaluating
them. This serves the purpose of an access cotrol list (ACL) by allowing these rules to grant access (return `True`),
explicitly deny access (return `False`), or abstain (return `None`). Additionally, values returned from endpoints will
have the value of their `__acl__` attribute evaluated, if present.

Also provided are a stock set of _predicates_ which allow for basic boolean logic, various nesting patterns, and
provide building blocks for more complex behaviour. It is preferred to access these via the `where` helper object,
whose attributes (also provided as a mapping) are the names of `entry_points` registered plugins.


## Operation

On any endpoint or object leading to an endpoint during _dispatch_, define an `__acl__` attribute or property which
provides an iterable (`set`, `list`, `tuple`, generator, etc.) of _predicate_ objects. Objects may also optionally
specify an `__acl_inherit__` attribute or property, which, if _falsy_, will clear the ACL that had been built so far
for the request.

After a final endpoint has been reached, these rules are evaluated in turn (using the `First` predicate), passing the
request context as their first argument.  Each is called until one either returns `True` to indicate permission has
been explicitly granted, or returns `False` to indicate permission has been explicitly denied. If no predicates decide
to have an opinion, the default action is configurable.


# Usage

## Enabling the Extension

Before utilizing access control list functionality in your own application you must first enable the extension.

Regardless of configuration route chosen rules may be specified as strings, classes, or callables. Strings are
resolved using the `web.acl.predicate` `entry_point` namespace and further processed. Classes (either directly, or
loaded by plugin name) are instantiated without arguments and their instance used.


### Imperative Configuration

Applications using code to explicitly construct the WebCore `Application` object, but with no particular custom base
ruleset needed, can pass the extension by name. It will be loaded using its `entry_points` plugin reference.

```python
app = Application("Hi.", extensions=['acl'])
```

Applications with a more strict configuration may wish to specify a default rule of `never`. Import the extension
yourself, and specify a default rule.

```python
from web.ext.acl import ACLExtension, when

app = Application("Hi.", extensions=[ACLExtension(default=when.never)])
```

More complex arrangements can be had by specifying rules positionally (their order will be preserved) or by passing a
`policy` iterable by name. These may be combined with the `default` named argument, with them being combined as
`positional` + `policy` + `default`.


### Declarative Configuration

Using a JSON or YAML-based configuration, you would define your application's `extensions` section either with the
bare extension declared:

```yaml
application:
	root: "Hi."
	
	extensions:
		acl:
```

Or, specify a default policy by treating the `acl` entry as an array:

```yaml
application:
	root: "Hi."
	
	extensions:
		acl:
			- never
```

By specifying a singular `default` explicitly:

```yaml
application:
	root: "Hi."
	
	extensions:
		acl:
			default: never
```

Or, finally, by specifying the `policy`, which must be an array, explicitly:

```yaml
application:
	root: "Hi."
	
	extensions:
		acl:
			policy:
				- never
```

Use of `policy` and `default` may be combined, with the default appended to the given policy.


## Defining ACLs

Note: We'll be using [object dispatch](https://github.com/marrow/web.dispatch.object/) for these examples.

First, you're going to need to `from web.ext.acl import when` to get easy access to predicates.


### Explicit Usage

Define an iterable of predicates using the `__acl__` attribute.

```python
class PermissiveController:
	__acl__ = [when.always]
	
	def __init__(self, context):
		pass
	
	def __call__(self):
		return "Hi."
```

For intermediary nodes in descent and return values, such as a "root controller with method" arrangement, you can
define an `__acl__` attribute. The contents of this attribute is collected during processing of dispatch events.


### Decoration

Using the `when` utility as a decorator or decorator generator.

```python
@when(when.never)
class SecureController:
	def __init__(self, context):
		pass
	
	@when(when.always, inherit=False)
	def insecure_resource(self):
		return "Yo."
	
	def __call__(self):
		return "Hi."
```

You can use the `when` predicate accessor as a decorator, defining the predicates for an object as positional
parameters.  The result of calling `when` can be saved used later as a decorator by itself, or as a filter to set that
attribute on other objects.


### Endpoint Return Values

Controlling access to information, not just endpoints.

```python
class Thing:
	__acl__ = [when.never]


def endpoint(context):
	return Thing()
```

In this example, `Thing` will not allow itself to be returned by an endpoint. This process is not recursive.
"""

from itertools import chain
from inspect import isclass
from pathlib import PurePosixPath as Path

from webob.exc import HTTPForbidden

from ..core.util import safe_name
from ..security import ACL, when


log = __import__('logging').getLogger(__name__)


class ACLExtension:
	"""Access control list extension.
	
	Predicates are gathered as dispatch descends through objects, collecting them from the `__acl__` attribute.
	If any object defines `__acl_inherit__` as a falsy value the ACL gathered so far is cleared before continuing.
	"""
	
	provides = {'acl'}
	extensions = {'web.security.predicate'}
	context = {'acl'}
	
	def __init__(self, *_policy, default=None, policy=None):
		"""Configure the ACL extension by defining an optional base policy.
		
		This policy will be used as the base for every request; these are evaluated first, always.
		"""
		
		super().__init__()
		
		if policy is None:
			policy = []
		
		if _policy:
			policy = chain(_policy, policy)
		
		policy = (when[rule] if isinstance(rule, str) else rule for rule in policy)
		policy = (rule() if isclass(rule) else rule for rule in policy)
		
		policy = self.policy = list(policy)
		
		if default:
			policy.append(default)
		
		log.info("ACL extension prepared with defualt policy: " + repr(policy))
	
	def prepare(self, context):
		"""Called to prepare the request context by adding an `acl` attribute."""
		
		if __debug__:
			log.debug("Preparing request context with ACL.", extra=dict(request=id(context)))
		
		context.acl = ACL(context=context, policy=self.policy)
	
	def dispatch(self, context, crumb):
		"""Called as dispatch descends into a tier.
		
		The ACL extension uses this to build up the current request's ACL.
		"""
		
		acl = getattr(handler, '__acl__', ())
		inherit = getattr(handler, '__acl_inherit__', True)
		
		if __debug__:
			log.debug(f"Handling dispatch event: {handler!r} {acl!r}", extra=dict(
					request = id(context),
					consumed = crumb.path,
					handler = safe_name(crumb.handler),
					endpoint = crumb.endpoint,
					acl = [repr(i) for i in acl],
					inherit = inherit,
				))
		
		if not inherit:
			if __debug__:
				log.debug("Clearing collected access control list.")
			
			del context.acl[:]
		
		context.acl.extend((Path(context.request.path), i, handler) for i in acl)
	
	def mutate(self, context, handler, args, kw):
		if not context.acl:
			if __debug__:
				log.debug("Skipping validation of empty ACL.", extra=dict(request=id(context)))
			
			return
		
		grant = context.acl.is_authorized
		
		if grant.result is False:
			log.error("Endpoint authorization failed: " + repr(grant), extra=dict(
					grant = False,
					predicate = repr(grant.predicate) if grant.predicate else None,
					path = str(grant.path) if grant.path else None,
					source = safe_name(grant.source) if grant.source else None
				))
			raise HTTPForbidden()
		
		elif __debug__:
			log.debug("Successful endpoint authorization: " + repr(grant), extra=dict(
					grant = False,
					predicate = repr(grant.predicate) if grant.predicate else None,
					path = str(grant.path) if grant.path else None,
					source = safe_name(grant.source) if grant.source else None
				))
	
	def transform(self, context, handler, result):
		try:
			acl = result.__acl__
		except AttributeError:
			return result
		
		acl = ACL(*acl, context=context)
		valid = acl.is_authorized
		
		if valid.result is False:
			log.error("Response rejected due to return value authorization failure.", extra=dict(
					grant = False,
					predicate = repr(valid.predicate) if valid.predicate else None,
					path = str(valid.path) if valid.path else None,
					result = safe_name(type(result))
				))
			return HTTPForbidden()
		
		elif __debug__:
			log.debug("Successful response authorization.", extra=dict(
					grant = valid.result,
					predicate = repr(valid.predicate) if valid.predicate else None,
					path = str(valid.path) if valid.path else None,
					result = safe_name(type(result))
				))
		
		return result
