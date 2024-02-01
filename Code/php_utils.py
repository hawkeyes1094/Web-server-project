import sys
import os
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

GET_ENV_VARS = {
	"QUERY_STRING": "",
	"SCRIPT_NAME": "",
	"SCRIPT_FILENAME": "",
	"REQUEST_METHOD": "GET",
	"REDIRECT_STATUS": '0',
	"REMOTE_HOST": ""
}

POST_ENV_VARS = {
	"QUERY_STRING": "",
	"SCRIPT_NAME": "",
	"SCRIPT_FILENAME": "",
	"REQUEST_METHOD": "POST",
	"GATEWAY_INTERFACE": "CGI/1.1",
	"REDIRECT_STATUS": '1',
	"CONTENT_TYPE": 'application/x-www-form-urlencoded',
	"CONTENT_LENGTH": '0',
	"REMOTE_HOST": ""
}

def ExecutePHP(php_path, request, addr):

	if request["method"] == "GET":
		GET_ENV_VARS["SCRIPT_NAME"] = php_path.name
		GET_ENV_VARS["SCRIPT_FILENAME"] =  str(php_path)
		if "request_uri_query" in request.keys():
			GET_ENV_VARS["QUERY_STRING"] = request["request_uri_query"]
		GET_ENV_VARS["REMOTE_HOST"] = addr[0]

		# php-cgi called with env vars: {"SCRIPT_NAME": php_path, "QUERY_STRING": request_query, "REQUEST_METHOD": http_method, "REDIRECT_STATUS": 0}
		get_proc_obj = subprocess.Popen(["php-cgi"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=GET_ENV_VARS)
		# Read stdout and stderr of the process. stderr would be b'' if empty
		php_get_stdout = get_proc_obj.stdout.read()
		php_get_stderr = get_proc_obj.stderr.read()

		return php_get_stdout
	
	elif request["method"] == "POST":
		POST_ENV_VARS["SCRIPT_NAME"] = php_path.name
		POST_ENV_VARS["SCRIPT_FILENAME"] = str(php_path)
		
		if "request_uri_query" in request.keys():
			POST_ENV_VARS["QUERY_STRING"] = request["request_uri_query"]
		
		POST_ENV_VARS["REMOTE_HOST"] = addr[0]
		POST_ENV_VARS["CONTENT_LENGTH"] = str(len(request["body"]))

		# Default value -> 'content-type': 'application/x-www-form-urlencoded'
		# This is DANGEROUS. Directly passing the value of content-type header to an environment variable
		if "content-type" in request["request_headers"].keys():
			POST_ENV_VARS["CONTENT_TYPE"] = request["request_headers"]["content-type"]
		
		post_proc_obj = subprocess.Popen(["php-cgi"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=POST_ENV_VARS)
		(php_post_stdout, php_post_stderr) = post_proc_obj.communicate(input=request["body"])

		return php_post_stdout