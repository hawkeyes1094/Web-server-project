def _ConstructHeaderText(headers):
	response = ""
	for field_name in headers.keys():
		response += "{}: {}\r\n".format(field_name, headers[field_name])

	return response

response_status_code_messages = {
	200: "HTTP/1.1 200 OK\r\n",
	201: "HTTP/1.1 201 Created\r\n",
	400: "HTTP/1.1 400 Bad Request\r\n",
	403: "HTTP/1.1 403 Forbidden\r\n",
	404: "HTTP/1.1 404 Not Found\r\n",
	405: "HTTP/1.1 405 Not Implemented\r\n",
	411: "HTTP/1.1 411 Length Required\r\n",
	500: "HTTP/1.1 500 Internal Server Error\r\n",
	501: "HTTP/1.1 501 Not Implemented\r\n",
	505: "HTTP/1.1 505 HTTP Version Not Supported\r\n"
}

def GenerateResponse(status_code, headers=None, body=None, headers_in_body=False):
	response = ''
	response += response_status_code_messages[status_code]
	if headers:
		response += _ConstructHeaderText(headers)
	else:
		response += "\r\n"
	
	response = response.encode('ascii')
	# body is a binary string
	if body:
		if not headers_in_body:
			response += b"\r\n"
		response += body

	return response
