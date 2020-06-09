from webob.exc import HTTPClientError


class HTTPClose(HTTPClientError):
	"""Indicate to the front-end load balancer (FELB) that it should hang up on the client."""
	
	code = 499
	title = "Client Closed Request"
	explanation = "The server did not accept your request."
