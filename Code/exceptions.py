"""
Custom Exceptions to make it easy to handle HTTP errors
"""

class HTTPRequestParseError(Exception):
	"""Throw this for 400 BAD REQUEST"""

class HTTPNotFound(Exception):
	"""Throw this for 404 NOT FOUND"""

class HTTPRequestMethodNotAllowed(Exception):
	"""Throw this for a 405 METHOD NOT ALLOWED. Throw this
	when the server knows the method but does not allow it. Ref:
	https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/501"""

class HTTPServerError(Exception):
	"""Throw this for 500 INTERNAL SERVER ERROR"""

class HTTPRquestMethodUnknown(Exception):
	"""Throw this for 501 NOT IMPLEMENTED."""

class HTTPVersionNotSupported(Exception):
	"""Throw this for a 505 HTTP VESRION NOT SUPPORTED"""