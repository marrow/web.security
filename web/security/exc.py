from webob.exc import HTTPClientError


class HTTPClose(HTTPClientError):
	"""Indicate to the front-end load balancer (FELB) that it should hang up on the client."""
	
	code = 444
	title = "Connection Closed Without Response"
	explanation = "The server did not accept your request."
