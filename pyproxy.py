#!/usr/bin/python3

import threading
import socket
import binascii
import random
import select
import argparse



def usage():
	if not silent:
		print("PyProxy - python SOCKS5 proxy")


def handle_proxy(initial_socket, local_ip_raw, target_address, target_port, ipv6_address, command):
	response_buffer = b''

	
	#Needed for BIND requests only?
	#(downstream_connection, downstream_connection_addr) = downstream_connection_server.accept()

	if debug:
		print("{*} - connection received from downstream")
		print("{*} - ipv6: ")
		print(ipv6_address)

	if ipv6_address:
		upstream_connection = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
	else:
		upstream_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	

	try:
		print(target_address)
		print(target_port)
		upstream_connection.connect((target_address, target_port))
	except:
		if debug:
			print("{*} - Connection to remote host failed")
			print("{*} - %s:%d" % (target_address, target_port))
		response_buffer = b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00'
		initial_socket.send(response_buffer)
		initial_socket.close()
		return(-1)
	
	if debug:
		print('{*} - connection established to %s %d' % (target_address, target_port))
	
	
	response_buffer = b'\x05\x00\x00'

	#this whole thing with 'downstream_connection is only for SOCKS BIND
	#requests; need to strip out and rebuild

	#we're only going to return ipv6 or ipv4 addresses, not FQDNs
	if ipv6_address:
		response_buffer += b'\x04'
	else:
		response_buffer += b'\x01'
	for octet in local_ip_raw.split('.'):
		response_buffer += int(octet).to_bytes(1, byteorder='big')
	
	downstream_connection_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


	#allow for the fact that some ports might be in use
#	while True:	
#		try:
#			server_port = random.randint(15000, 55000)
#			downstream_connection_server.bind((local_ip_raw, server_port))
#		except socket.error as e:
#			if e.errno == errno.EADDRINUSE:
#				if verbose:
#					print('{*} Socket already in use; trying again')
#				continue
#		break
#
#	if debug:
#		print('{*} - opening port for downstream')
#
#	downstream_connection_server.listen(5)


#	if verbose:
#		print('{*} - listening now on port %d' % server_port)

	server_port = upstream_connection.getsockname()[1]
	response_buffer += int(server_port).to_bytes(2, byteorder='big')

	initial_socket.send(response_buffer)
	
	if debug:
		print("{*} - sent response_buffer")


	while True:
		r, w, e = select.select([initial_socket, upstream_connection], [],[])
		
		if initial_socket in r:
			data = initial_socket.recv(4096)
			if upstream_connection.send(data) <= 0:
				break

		if upstream_connection in r:
			data = upstream_connection.recv(4096)
			if initial_socket.send(data) <= 0:
				break

			
	
	

def handle_initial_request(client_socket):
	
	request_buffer = b''
	init = True
	no_auth = False
	ipv6_address = False

	if debug:
		print("handle_initial_request")

	#accept the intial request, with authentication negotiation
	while True:
	
		data = client_socket.recv(4)

		if debug and init:
			print("foo")
			print(data)

		if not data:
			break
		elif len(data) <= 4:
			request_buffer += data
			data =''
			break
		else:
			request_buffer += data
			data =''
		
	if debug:
		print("{*} received; %s" % request_buffer)

	#accept only SOCKS5 requests
	if request_buffer[0] != 5:
		if verbose:
			print("{*} - not a SOCKS5 request")
		client_socket.close()
		return(-1)
	
	#num_methods = int.from_bytes(request_buffer[1], byteorder='big')
	num_methods = request_buffer[1]
	if debug:
		print(num_methods)

	for method in request_buffer[2:]:
		print('bar')
		if debug:
			print(method)
		#This only handles No Authentication as a method right now
		if method == 0:

			no_auth = True
			break

	if no_auth:
		client_socket.send(b'\x05\x00')
	else:
		client_socket.send(b'\x05\xFF')
		if verbose:
			print("{*} - no mutually acceptable authentication method")
		client_socket.close()
		return(-1)
			

	request_buffer = b''
	data = b''
	#accept the inital connection request
	while True:
	
		data = client_socket.recv(4)


		if not data:
			break
		elif len(data) < 4:
			request_buffer += data
			data =''
			break
		else:
			request_buffer += data
			data = ''

		
	if debug:
		print("{*} received; %s" % request_buffer)

	if request_buffer[0] != 5:
		if verbose:
			print("{*} - malformed request")
		client_socket.close()
		return(-1)
	if not (request_buffer[1] == 1 or request_buffer[1] == 2 or request_buffer[1] == 3):
		if verbose:
			print("{*} - malformed request")
		client_socket.close()
		return(-1)
	command = request_buffer[1]	
	if request_buffer[2] != 0:
		if verbose:
			print("{*} - malformed request")
		client_socket.close()
		return(-1)
	if not (request_buffer[3] == 1 or request_buffer[3] == 3 or request_buffer[3] == 4):
		if verbose:
			print("{*} - malformed request")
		client_socket.close()
		return(-1)
	#handle ipv4 address
	if request_buffer[3] == 1:
		target_address = ''
		if debug:
			print(request_buffer[4:7])
		for octet_raw in request_buffer[4:8]:
			if debug:
				print("{*} - Decoding ipv4 address")
				print(octet_raw)
				#print(octet_raw[0])
			#octet = int.from_bytes(octet_raw, byteorder='big')
			#octet = octet_raw[0]
			octet = octet_raw
			if not 0<= octet <= 255:
				if verbose:
					print("{*} - bad target IP address")
				client_socket.close()
				return(-1)
			
			
			target_address += str(octet)
			target_address +='.' 
		target_address = target_address[:len(target_address) - 1]
		if debug:
			print("{*} - target address: %s" % target_address)
	#handle DNS hostname
	if request_buffer[3] == 3:
		target_address_len = int.from_bytes(request_buffer[4], byteorder='big')
		if target_address_len + 5 != (len(request_buffer) - 2):
			if verbose:
				print("{*} - malformed request")
			client_socket.close()
			return(-1)
		target_adddress = request_buffer[5:5+target_address_len]
		if verbose:
			print('{*} - target address: %s' % target_address)
	#handle ipv6 address
	if request_buffer[3] == 4:
		target_address = ''
		if len(request_buffer) != 22:
			if verbose:
				print("{*} - malformed request")
			client_socket.close()
			return(-1)
		for octet_raw in request_buffer[5:20]:
			octet = octet_raw.hex()
			target_address += octet + ':'
		target_address = target_address[:len(target_address) - 1]
		ipv6_address = True
	target_port = int.from_bytes(request_buffer[len(request_buffer) -2:], byteorder='big')
	if debug:
		print("{*} - port: %d" % target_port)
	if not 1 <= target_port <= 65535:
		if verbose:
			print("{*} - malformed request")
		client_socket.close()
		return(-1)
	
	local_address = client_socket.getsockname()[0]
	
	proxy_handler = threading.Thread(target=handle_proxy, args=(client_socket, local_address, target_address, target_port, ipv6_address,command,))
	proxy_handler.start()


def valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except:
        return False




def main():
	
	global allowed_src_ip 
	allowed_src_ip = "127.0.0.1"
	global bind_ip 
	bind_ip = "0.0.0.0"
	global bind_port 
	bind_port = 9999

	global verbose
	verbose = True
	global silent 
	silent = False
	global debug
	debug = False

	parser = argparse.ArgumentParser(description='Start a simple SOCKS5 proxy')
	parser.add_argument('-a', '--allowed_ip', help="IP address allowed to connect to the proxy. Defaults to 127.0.0.1")
	parser.add_argument('-p', '--port', type=int, help="Port to listen on")
	parser.add_argument('-b', '--bind_ip', help="Listening IP address. Defaults to 0.0.0.0 (all interfaces).")

	args = parser.parse_args()

	if args.allowed_ip:
		if valid_ip(args.allowed_ip):
			allowed_src_ip = args.allowed_ip
		else:
			print("Invalid allowed IP address")
			exit(-1)

	if args.port:
		if args.port > 0 and args.port < 65355:
			bind_port = args.port
		else:
			print("Invalid port")
			exit(-1)
	
	if args.bind_ip:
		if valid_ip(args.bind_ip):
			bind_ip = args.bind_ip
		else:
			print("Invalid bind IP address")
			exit(-1)


	#initialize the server
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	server.bind((bind_ip, bind_port))
	
	server.listen(5)
	
	if verbose:
		print("[*] Listening on %s:%d" %(bind_ip, bind_port))
	
	
	while True:
	
		(client,addr) = server.accept()

		if addr[0] != allowed_src_ip:
			if verbose:
				print("[*] Connection attempted from non-allowed ip: %s, dropped" % addr)
			client.close()
	
		if verbose:
			print("[*] Accepted connection from %s:%d" % (addr[0], addr[1]))
		client_handler = threading.Thread(target=handle_initial_request,args=(client,))
		client_handler.start()


main()
