#!/usr/bin/python3
"""Code to listen to on an interface for HTTP requests"""

import os
import sys
import socket
import ssl
import logging
from pathlib import Path
# custom imports
import handle_request

logging.basicConfig(level=logging.DEBUG,
	filename="output.log")
logger = logging.getLogger(__name__)

web_server_path = Path().cwd()

def ConnHandler(conn, addr):

	global web_server_path
	# buffer = b''
	# while True:
	# 	data = conn.recv(4096)
	# 	if not data:
	# 		break
	# 	buffer += data
	data = conn.recv(4096)
	print("starting request handler")
	response = handle_request.RequestHandler(data, addr, web_server_path)
	conn.sendall(response)
	conn.close()
	
	return

def Listen(ipaddr, port, certpath=None, privkeypath=None):

	context = None
	if certpath and privkeypath:
		context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		context.load_cert_chain(str(certpath), str(privkeypath), password=None)
		# context.minimum_version(ssl.TLSVersion.TLSv1_2)

	try:
		# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# sock.bind((ipaddr, port))

		sock = socket.create_server((ipaddr, port), family=socket.AF_INET)
		sock.listen()
		if context:
				ssock = context.wrap_socket(sock, server_side=True)

		while True:
			if context:
				conn, addr = ssock.accept()
			else:
				conn, addr = sock.accept()
			print("Accepted connection from {}".format(addr))
			
			ConnHandler(conn, addr)

	except ssl.SSLError as ssl_e:
		# print("Error while connecting using SSL")
		print(ssl_e)

	except KeyboardInterrupt as ke:
		# conn.close()
		# ssock.close()
		# sock.close()
		print("Keyboard interrupt received")
		sys.exit(-1)
	
	return


def main():

	if len(sys.argv) == 3:
		ipaddr = sys.argv[1]
		port = sys.argv[2]
		certpath = None
		privkeypath = None
	
	elif len(sys.argv) == 5:
		ipaddr = sys.argv[1]
		port = sys.argv[2]
		certpath = Path(sys.argv[3]).resolve()
		if not certpath.exists():
			print("Certificate file does not exist. Exiting...")
			sys.exit(-1)
		privkeypath = Path(sys.argv[4])
		if not privkeypath.exists():
			print("Private key file does not exist. Exiting...")
			sys.exit(-1)
	
	else:
		print("Please provide arguements in the following format:")
		print("<ipaddress> <port> </path/to/cert/file> </path/to/private/key/file>")
		sys.exit(-1)

	try:
		socket.inet_aton(ipaddr)
	except OSError as e:
		print("IP address in invalid")
		sys.exit(-1)
	
	if not port.isnumeric() or int(port) < 1 or int(port) > 65535:
		print("Enter a valid port number")
		sys.exit(-1)
	port = int(port)

	Listen(ipaddr, port, certpath, privkeypath)

	return

if __name__ == "__main__":
	main()