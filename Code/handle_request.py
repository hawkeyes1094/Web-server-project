import os
import sys
import logging
from pathlib import Path
#custom imports
import response_codes
import parse
import php_utils

logger = logging.getLogger(__name__)

"""
The request is parsed into a dictionary for easy handling. Sample dictionary -
{
	"body": b'<html>\r\nabcd\r\n<!html>',
	"body_length": 21,
   "response":{
	  "code":200,
	  "message":"HTTP/1.1 200 OK\r\n"
   },
   "method":"GET",
   "request_uri_path":"/sample.html",
   "request_uri_query":"abcd=def&ghi=jkl",
   "request_uri_type":"abs_path",
   "http_version":"HTTP/1.1",
   "request_headers":{
	  "Host":"localhost",
	  "User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:103.0) Gecko/20100101 Firefox/103.0",
	  "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	  "Accept-Language":"en-US,en;q=0.5",
	  "Accept-Encoding":"gzip, deflate, br",
	  "Connection":"keep-alive",
	  "Cookie":"PHPSESSID=k7ntiv9br8jshjlln3d6ss5ql5; security=low",
	  "Upgrade-Insecure-Requests":"1",
	  "Sec-Fetch-Dest":"document",
	  "Sec-Fetch-Mode":"navigate",
	  "Sec-Fetch-Site":"none",
	  "Sec-Fetch-User":"?1"
   }
}
"""

web_server_path = ""

def GET(request, addr):

	if request["request_uri_type"] != "abs_path":
		return response_codes.GenerateResponse(400)

	# convert abs_path to PosixPath and resolve it
	requested_path = Path(str(web_server_path) + "/webroot/" + request["request_uri_path"].strip('/')).resolve()
	current_path = Path(str(web_server_path) + "/webroot").resolve()

	# Happens when abs_path is '/' and requested path is set to Path('') => Path'(<current-working-dir>')
	if requested_path == current_path:
		requested_path = Path(str(web_server_path) + "/webroot/index.html").resolve()
	
	#check if the current working directory is parent of the requested path
	# Commented the below code to add an LFI vuln in the GET method
	# if current_path not in requested_path.parents:
	# 	return response_codes.GenerateResponse(403)
	
	# return 404.html when a 404 is triggered
	if not requested_path.is_file() or not requested_path.exists():
		try:
			with open(str(web_server_path) + "webroot/404.html", 'r') as f:
				resp_body = f.read()
				resp_body = resp_body.encode()
				resp_body_headers = {"content-length": len(resp_body)}
				return response_codes.GenerateResponse(404, resp_body_headers, resp_body)

		except Exception as e:
			return response_codes.GenerateResponse(500)

	if not os.access(requested_path, os.R_OK):
		return response_codes.GenerateResponse(403)
	
	if requested_path.suffix == '.php':
		resp_body = php_utils.ExecutePHP(requested_path, request, addr)
		resp_body_headers = {"content-length": len(resp_body)}
		# headers_in_body param is a last minute bug fix. A clean fix would need a rework of this code
		return response_codes.GenerateResponse(200, resp_body_headers, resp_body, headers_in_body=True)
	else:
		try:
			with open(requested_path, 'r') as f:
				resp_body = f.read()
				resp_body = resp_body.encode()
				resp_body_headers = {"content-length": len(resp_body)}
				return response_codes.GenerateResponse(200, resp_body_headers, resp_body)

		except Exception as e:
			return response_codes.GenerateResponse(500)


# using post to modify an existing file
def POST(request, addr):

	if not 'content-length' in request['request_headers'].keys() or not request['request_headers']['content-length']:
		return response_codes.GenerateResponse(411)

	# check if the content-length header field contains a number
	if not request['request_headers']['content-length'].isnumeric():
		return response_codes.GenerateResponse(400)

	requested_path = Path(str(web_server_path) + "/webroot/" + request["request_uri_path"].strip('/')).resolve()
	current_path = Path(str(web_server_path) + "/webroot").resolve()

	if current_path not in requested_path.parents:
		return response_codes.GenerateResponse(403)
	if not requested_path.is_file() or not requested_path.exists():
		return response_codes.GenerateResponse(404)
	if not os.access(requested_path, os.R_OK) or not os.access(requested_path, os.W_OK):
		return response_codes.GenerateResponse(403)

	# check if the request body contains more bytes than indicated in content-length
	if request['body_length'] < int(request['request_headers']['content-length']):
		body_len = request['body_length']
	else:
		body_len = int(request['request_headers']['content-length'])

	body = request["body"][0:body_len]

	if requested_path.suffix == '.php':
		resp_body = php_utils.ExecutePHP(requested_path, request, addr)
		resp_body_headers = {"content-length": len(resp_body)}
		# headers_in_body param is a last minute bug fix. A clean fix would need a rework of this code
		return response_codes.GenerateResponse(200, resp_body_headers, resp_body, headers_in_body=True)
	try:
		with open(requested_path, 'wb') as f:
			f.write(body)
			f.flush()
		return response_codes.GenerateResponse(200)
	except Exception as e:
		return response_codes.GenerateResponse(500)


# using put to create a new file
def PUT(request, addr):

	if not 'content-length' in request['request_headers'].keys() or not request['request_headers']['content-length']:
		return response_codes.GenerateResponse(411)

	# check if the content-length header field contains a number
	if not request['request_headers']['content-length'].isnumeric():
		return response_codes.GenerateResponse(400)

	requested_path = Path(str(web_server_path) + "/webroot/" + request["request_uri_path"].strip('/')).resolve()
	current_path = Path(str(web_server_path) + "/webroot").resolve()

	if current_path not in requested_path.parents:
		return response_codes.GenerateResponse(403)

	# check if the request body contains more bytes than indicated in content-length
	if request['body_length'] < int(request['request_headers']['content-length']):
		body_len = request['body_length']
	else:
		body_len = int(request['request_headers']['content-length'])

	body = request["body"][0:body_len]

	if requested_path.exists():
		try:
			with open(requested_path, 'wb') as f:
				f.write(body)
			# As per RFC 2616, send a 200 when an existing resource is modified
			return response_codes.GenerateResponse(200)
		except Exception as e:
			return response_codes.GenerateResponse(500)
	else:
		# create directories requested by the PUT request
		if not requested_path.parent.exists():
			requested_path.parent.mkdir(parents=True)
		try:
			with open(requested_path, 'wb') as f:
				f.write(body)
				f.flush()
			# path of new file relative to webroot: requested_path - current_path
			newfile_location = str(requested_path).replace(str(current_path), '')
			headers = {"location": newfile_location}
			return response_codes.GenerateResponse(201, headers, body)

		except Exception as e:
			return response_codes.GenerateResponse(500)


def DELETE(request, addr):

	requested_path = Path(str(web_server_path) + "/webroot/" + request["request_uri_path"].strip('/')).resolve()
	current_path = Path(str(web_server_path) + "/webroot").resolve()

	if current_path not in requested_path.parents:
		return response_codes.GenerateResponse(403)

	if not requested_path.exists():
		return response_codes.GenerateResponse(404)
	
	# Just to ensure code files are not accidentally deleted
	if str(requested_path).endswith(".py"):
		return response_codes.GenerateResponse(404)

	try:
		requested_path.unlink()
		return response_codes.GenerateResponse(200)
	except Exception as e:
		return response_codes.GenerateResponse(500)

def RequestHandler(data, addr, server_path):

	global web_server_path
	web_server_path = server_path

	response = b''

	request = parse.ParseRequest(data)
	if request["response"]["code"] != 200:
		response = request["response"]["message"].encode('ascii')
	else:
		if request["method"] == "GET":
			response = GET(request, addr)
		elif request["method"] == "POST":
			response = POST(request, addr)
		elif request["method"] == "PUT":
			response = PUT(request, addr)
		elif request["method"] == "DELETE":
			response = DELETE(request, addr)
	
	return response

def main():

	request_file = sys.argv[1]

	try:
		with open(request_file, 'rb') as f:
			raw_request = f.read()
	except Exception as e:
		logger.exception("Error opening file")
	
	print(RequestHandler(raw_request).decode())

if __name__=="__main__":
	main()