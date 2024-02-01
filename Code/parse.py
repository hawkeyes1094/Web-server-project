"""Code to parse a HTTP request"""

import sys
import logging
import re
from exceptions import *
import pprint

logger = logging.getLogger(__name__)

HTTP_ALLOWED_METHODS = ['GET', 'PUT', 'POST', 'DELETE']
HTTP_METHODS_NOT_IMPLEMENTED = ['HEAD', 'CONNECT']
SUPPORTED_HTTP_VERSIONS = ['HTTP/1.0', 'HTTP/1.1']
ALLOWED_SCHEMES = ['http', 'https']
RESERVED_CHARS = [";", "/", ":", "@", "&", "=", "+", "$", ","]

# regex to check whether a URI contains only allowed chars
# Quick and dirty hack for unsafe chars check
# uri_allowed_charset = re.compile(r'[^A-Za-z0-9\-._~;/:@&=+,#?%]')


# WARNING!! - Painful regex ahead
IPV4_PATTERN = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

"""
	authority     = server | reg_name
	server        = [ [ userinfo "@" ] hostport ] #I'm ignoring userinfo
	hostport      = host [ ":" port ]
	host          = hostname | IPv4address
	hostname      = *( domainlabel "." ) toplabel [ "." ]
	domainlabel   = alphanum | alphanum *( alphanum | "-" ) alphanum
	toplabel      = alpha | alpha *( alphanum | "-" ) alphanum
	IPv4address   = 1*digit "." 1*digit "." 1*digit "." 1*digit
	port          = *digit
	reg_name      = 1*( unreserved | escaped | "$" | "," |
						  ";" | ":" | "@" | "&" | "=" | "+" )
	reserved      = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+" | "$" | ","
	unreserved    = alphanum | mark
	mark          = "-" | "_" | "." | "!" | "~" | "*" | "'" | "(" | ")"
	escaped       = "%" hex hex
"""
DOMAINLABEL_PATTERN = r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?"
TOPLABEL_PATTERN = r"[a-zA-Z](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?"
HOSTNAME_PATTERN = r"^(?:" + DOMAINLABEL_PATTERN + r"\.)*" + TOPLABEL_PATTERN + r"(?:\.)?"
HOST_PATERN = HOSTNAME_PATTERN + r"|" + IPV4_PATTERN
HOSTPORT_PATTERN = r"(?:" + HOST_PATERN + r")(?::\d+)?"
SERVER_PATTERN = r"(" + HOSTPORT_PATTERN + r")?"
SERVER_REGEX = re.compile(SERVER_PATTERN)

ESCAPED_PATTERN = r"\%[a-fA-F0-9][a-fA-F0-9]"
ESCAPED_REGEX = re.compile(ESCAPED_PATTERN)
UNRESERVED_PATTERN = r"[a-zA-Z0-9\-_.!~*'()]"
RESERVED_PATTERN = r"[;/?:@&=+$,]"
REG_NAME_PATTERN = r"(?:" + UNRESERVED_PATTERN + r"|" + ESCAPED_PATTERN + r"|[$,;:@&=+])+"
REG_NAME_REGEX = re.compile(REG_NAME_PATTERN)

"""
	path_segments = segment *( "/" segment )
	segment       = *pchar *( ";" param )
	param         = *pchar
	pchar         = unreserved | escaped |
					  ":" | "@" | "&" | "=" | "+" | "$" | ","
"""
PCHAR_PATTERN   = UNRESERVED_PATTERN + r"|" + ESCAPED_PATTERN + r"|" + r"[\:@&=+$,]"
PARAM_PATTERN   = r"(?:" + PCHAR_PATTERN + r")*"
SEGMENT_PATTERN = r"(?:" + PCHAR_PATTERN + r")*(?:;" + PARAM_PATTERN + r")*"
PATH_SEGMENTS_PATTERN = r"(" + SEGMENT_PATTERN + r")(/" + SEGMENT_PATTERN + r")*"
PATH_SEGMENTS_REGEX = re.compile(PATH_SEGMENTS_PATTERN)

"""
	uric          = reserved | unreserved | escaped
	query         = *uric
"""
URIC_PATTERN = RESERVED_PATTERN + r"|" + UNRESERVED_PATTERN + r"|" + ESCAPED_PATTERN
QUERY_PATTERN = r"(?:" + URIC_PATTERN + r")*"
QUERY_REGEX = re.compile(QUERY_PATTERN)

"""
separators     = "(" | ")" | "<" | ">" | "@"
                | "," | ";" | ":" | "\" | <">
                | "/" | "[" | "]" | "?" | "="
                | "{" | "}" | SP | HT
"""
SEPARATORS_PATTERN = r"[()<>@,;:\\\"/\[\]?={} \t]"
SEPARATORS_REGEX = re.compile(SEPARATORS_PATTERN)

""" RFC 2396 Appendix B Parsing a URI Reference with a Regular Expression
	^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?
	12            3  4          5       6  7        8 9
	scheme    = $2
	authority = $4
	path      = $5
	query     = $7
	fragment  = $9
"""
URI_REGEX = re.compile(r"^(([^:\/\/?#]+):)?(\/\/([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?")
# End of painful regex.

# def decodeHexEncoding(encoded_data):
# 	decoded_data = ""
# 	start = 0
# 	for match in re.finditer(ESCAPED_REGEX, encoded_data):
# 		temp = encoded_data[start:match.start()]
# 		try:
# 			temp += bytes.fromhex(encoded_data[match.start()+1:match.end()]).decode("ascii")
# 		except UnicodeDecodeError as e:
# 			temp += "\u" + encoded_data[match.start()+1:match.end()]
# 		decoded_data += temp
# 		start = match.end()
# 	decoded_data += encoded_data[start:]
# 	return decoded_data


"""
	query         = *uric
"""
def isQuery(query):
	if QUERY_REGEX.fullmatch(query):
		return True
	else:
		return False


"""
	abs_path      = "/"  path_segments
"""
def isAbsPath(path):
	if path[0] == "/" and PATH_SEGMENTS_REGEX.fullmatch(path[1:]):
		return True
	else:
		return False


""" 
	authority     = server | reg_name
"""
def isAuthority(authority):
	if SERVER_REGEX.fullmatch(authority) or REG_NAME_REGEX.fullmatch(authority):
		return True
	else:
		return False


"""
	Request-URI    = "*" | absoluteURI | abs_path | authority
	URI-reference = [ absoluteURI | relativeURI ] [ "#" fragment ]
    absoluteURI   = scheme ":" ( hier_part | opaque_part )
    hier_part     = ( net_path | abs_path ) [ "?" query ]
    opaque_part   = uric_no_slash *uric
    uric_no_slash = unreserved | escaped | ";" | "?" | ":" |
					 "@" | "&" | "=" | "+" | "$" | ","
    net_path      = "//" authority [ abs_path ]
    abs_path      = "/"  path_segments
	
	absoluteURI = scheme ":" ( "//" authority [ abs_path ] | abs_path ) [ "?" query ]
"""
def ParseRequestURI(uri, request):
	
	if uri == "*":
		request["request_uri"] = "*"
		return

	match_obj = URI_REGEX.match(uri)

	scheme = match_obj.group(2)
	authority = match_obj.group(4)
	path = match_obj.group(5)
	query = match_obj.group(7)
	fragment = match_obj.group(9)

	# absoluteURI parsing
	if scheme:
		if scheme not in ALLOWED_SCHEMES:
			raise HTTPRequestParseError
		if not authority or authority == '':
			raise HTTPRequestParseError
		
		request["request_uri_scheme"] = scheme

		if authority:
			if isAuthority(authority):
				request["request_uri_authority"] = authority
			else:
				raise HTTPRequestParseError
			if path:
				if isAbsPath(path):
					request["request_uri_path"] = path
				else:
					raise HTTPRequestParseError

		elif path:
			if isAbsPath(path):
				request["request_uri_path"] = path
			else:
				raise HTTPRequestParseError
		
		else:
			raise HTTPRequestParseError

		request["request_uri_type"] = "absoluteURI"
		# If abosulteURI does not end with a /, assume it does
		if path == '':
			path = '/'
			request["request_uri_path"] = path
		
		if query:
			if isQuery(query):
				request["request_uri_query"] = query

		return
	
	# abs_path
	elif uri[0] == "/":

		# "/www/abcd" -> authority = None, path = "/www/abcd"
		# "//www/abcd" -> authority = "www", path = "/abcd"
		# "///www/abcd" -> authority = "", path = "/www/abcd"
		# "////www/abcd" -> authority = "", path = "//www/abcd"
		if authority:
			path = "/" + authority + path
		
		if isAbsPath(path):
			request["request_uri_path"] = path
			if query:
				if isQuery(query):
					request["request_uri_query"] = query
				else:
					raise HTTPRequestParseError
		else:
			raise HTTPRequestParseError
		
		request["request_uri_type"] = "abs_path"

		if query: # Not in the RFC, but why???
			if isQuery(query):
				request["request_uri_query"] = query

	# authority
	elif isAuthority(uri):
		request["request_uri_authority"] = uri
		request["request_uri_type"] = "authority"

	else:
		raise HTTPRequestParseError


"""
Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
"""
def ParseRequestLine(request_line, request):
	
	request["request_line"] = request_line
	request_line_data = request_line.split(" ")
	
	if len(request_line_data) != 3:
		raise HTTPRequestParseError
	if request_line_data[0] not in HTTP_ALLOWED_METHODS:
		if request_line_data[0] in HTTP_METHODS_NOT_IMPLEMENTED:
			# Method not allowed since not implemented
			raise HTTPRequestMethodNotAllowed
		else:
			# The HTTP method is unknown
			raise HTTPRquestMethodUnknown
	
	request["method"] = request_line_data[0]

	ParseRequestURI(request_line_data[1], request)



	if request_line_data[2] not in SUPPORTED_HTTP_VERSIONS:
		raise HTTPVersionNotSupported
	
	request["http_version"] = request_line_data[2]

	return


"""
generic-message = start-line
                *(message-header CRLF)
                CRLF
                [ message-body ]
Request       = Request-Line
                *(( general-header | request-header | entity-header ) CRLF)
                CRLF
                [ message-body ]

message-header = field-name ":" [ field-value ]
field-name     = token
field-value    = *( field-content | LWS )
field-content  = <the OCTETs making up the field-value
				 and consisting of either *TEXT or combinations
				 of token, separators, and quoted-string>

token          = 1*<any CHAR except CTLs or separators>
"""
def ParseRequestHeader(header, request):
	header_split_data = header.split(':', 1)
	if len(header_split_data) != 2:
		raise HTTPRequestParseError
	
	# since header field names are not case-sensitive, convert all
	# to lower case for easier search/compare
	field_name = header_split_data[0].lower()
	if SEPARATORS_REGEX.search(field_name):
		raise HTTPRequestParseError
	# remove leading whitespaces
	field_value = header_split_data[1].strip()
	if "request_headers" in request.keys():
		request["request_headers"][field_name] = field_value
	else:
		request["request_headers"] = {field_name: field_value}
	
	return


""" RFC 2616 Section 5
	Request       = Request-Line              ; Section 5.1
					*(( general-header        ; Section 4.5
					 | request-header         ; Section 5.3
					 | entity-header ) CRLF)  ; Section 7.1
					CRLF
					[ message-body ]          ; Section 4.3
"""
def ParseHTTPHeader(header, request):

	# This project only supports ASCII encoded HTTP headers.
	try:
		header_str = header.decode('ascii')
	# Handle non-ASCII data in headers
	except UnicodeDecodeError as e:
		raise HTTPRequestParseError
	
	header_lines = header_str.split('\r\n')

	# In the interest of robustness, servers SHOULD ignore any empty
	# line(s) received where a Request-Line is expected.
	if header_lines[0] == '':
		header_lines.pop(0)
	
	request_line = header_lines[0]
	ParseRequestLine(request_line, request)
	headers = header_lines[1:]
	for header in headers:
		ParseRequestHeader(header, request)


def ParseRequest(data):
	
	request = {}
	request["response"] = {}
	split_res = data.split(b'\r\n\r\n', maxsplit=1)
	header = split_res[0]
	try:
		ParseHTTPHeader(header, request)
		logger.info("Valid Request received: {}".format(request["request_line"]))
		request["response"]["code"] = 200
		request["response"]["message"] = "HTTP/1.1 200 OK\r\n"

		if split_res[1]:
			request["body"] = split_res[1]
			request["body_length"] = len(split_res[1])
	
	except HTTPRequestParseError as e:
		request["response"]["code"] = 400
		request["response"]["message"] = "HTTP/1.1 400 Bad Request\r\n\r\n"
	
	except HTTPRequestMethodNotAllowed as e:
		request["response"]["code"] = 405
		request["response"]["message"] = "HTTP/1.1 405 Method Not Allowed\r\n\r\n"
	
	except HTTPRquestMethodUnknown as e:
		request["response"]["code"] = 501
		request["response"]["message"] = "HTTP/1.1 501 Not Implemented\r\n\r\n"
	
	except HTTPVersionNotSupported as e:
		request["response"]["code"] = 505
		request["response"]["message"] = "HTTP/1.1 505 HTTP Version Not Supported\r\n\r\n"

	except (HTTPServerError, Exception) as e:
		request["response"]["code"] = 500
		request["response"]["message"] = "HTTP/1.1 500 Internal Server Error\r\n\r\n"
	
	return request


def main():
	
	#  log_format = "%(asctime)s::%(levelname)s::%(name)s::"\
	#           "%(filename)s::%(lineno)d::%(message)s"
	logging.basicConfig(
		level=logging.DEBUG,
		format="%(levelname)s::%(filename)s::::%(lineno)d::%(message)s"
	)

	if len(sys.argv) != 2:
		print("python3 parse.py <request-filename>")
		print("Exiting...")
		exit(-1)
	
	request_file = sys.argv[1]

	try:
		with open(request_file, 'rb') as f:
			raw_request = f.read()
	except Exception as e:
		logger.exception("Error opening file")
	
	# Separate header and body. This is done since header and body may have
	# different encodings. This assumes that header and body are ALWAYS
	# separated by a '\r\n\r\n'. Not ideal when there are no headers.
	# split_res = raw_request.split(b'\r\n\r\n', maxsplit=1)
	# header = split_res[0]

	# request = {}
	try:
		request = ParseRequest(raw_request)
	
	except HTTPRequestParseError as e:
		return "HTTP/1.1 400 Bad Request\r\n"
	
	except HTTPRequestMethodNotAllowed as e:
		return "HTTP/1.1 405 Method Not Allowed\r\n"
	
	except HTTPRquestMethodUnknown as e:
		return "HTTP/1.1 501 Not Implemented\r\n"
	
	except HTTPVersionNotSupported as e:
		return "HTTP/1.1 505 HTTP Version Not Supported"

	except (HTTPServerError, Exception) as e:
		return "HTTP/1.1 500 Internal Server Error\r\n"


	# Handle body if it exists
	# if split_res[1]:
	# 	req_body = split_res[1]
		#ParseHTTPBody(req_body)

	return request


if __name__ == '__main__':
	retval = main()
	pprint.pprint(retval)