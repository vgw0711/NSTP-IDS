import socket
import sys
import nstp_v2_pb2
import time
from _thread import *
import threading


sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)      #Can be unsafe practice but for now for clarity of code lets keep it here
blacklist = []
open_fd = {}      #Confused whether to increment on every client_to_server or for every same ip and different port. Check in the end
threshold_tracker = {}
threshold = 150   #Change Afterwards
#Do all the improvisations at the end in the copy of this code. Improvisations as in providing the function only the things it needs rather than complete event

class Checker:                                         #Checker Class : 0-Deny 1-Allow 2-Terminate
	def path_checker(path):
		path_array = path.split('/')
		if path[0] == '/' or path_array[0] == '..':
			return 0
		root_count = 1
		for val in path_array:
			if root_count == 0:
				return 0
			if val == '':
				return 0
			if val == '..':
				root_count = root_count - 1
			else:
				root_count = root_count + 1
		return 1

	def client_hello_checker(event):                      #If open_fd[key] is 1 then client_hello established is set
		key = (event.remote_address,event.remote_port,event.address_family)
		if open_fd[key] != 1:                            #Client_Hello established checker
			open_fd[key] = 1
			if event.client_hello.major_version == 2:
				return 1
		return 0

	def ping_request_checker(event):
		key = (event.remote_address,event.remote_port,event.address_family)
		if open_fd[key] != 1:                           #Out-of-phase check
			return 0
		return 1

	def load_request_checker(event):
		key = (event.remote_address,event.remote_port,event.address_family)
		if open_fd[key] != 1:                           #Out-of-phase check
			print("A")
			return 0
		print("B")
		return Checker.path_checker(event.load_request.key)

	def store_request_checker(event):
		key = (event.remote_address,event.remote_port,event.address_family)
		if open_fd[key] != 1:                           #Out-of-phase check
			return 0
		if len(event.store_request.key)>512:            #Ensure the size printed is correct
			return 0
		return Checker.path_checker(event.store_request.key)

def perform_checks(event):
		event_name = event.WhichOneof('event')
		check_response = getattr(Checker,event_name+"_checker")(event)
		return check_response

def threshold_checker(remote_address):
	if threshold_tracker.get(remote_address) is None:
		threshold_tracker[remote_address] = 1
		return False
	val = threshold_tracker[remote_address]
	threshold_tracker[remote_address] = val + 1
	if threshold_tracker[remote_address] > threshold:
		return True
	return False

def open_fd_add(event):
	key = (event.remote_address,event.remote_port,event.address_family)
	if open_fd.get(key) is None:
		open_fd[key] = 0
		return False
	return True

def open_fd_remove(remote_address,remote_port,address_family):
	key = (remote_address,remote_port,address_family)
	if open_fd.get(key) != None :
		del open_fd[key]
	return

def add_to_blacklist(remote_address):
	if(remote_address in blacklist):
		return 1
	blacklist.append((remote_address))
	return 0

def blacklist_checker(remote_address):
	return (remote_address) in blacklist

def terminator(event,remote_port,address_family):
	ids_msg = nstp_v2_pb2.IDSMessage()
	ids_msg.terminate_connection.server_address = event.server_address
	ids_msg.terminate_connection.server_port = event.server_port
	ids_msg.terminate_connection.remote_address = event.remote_address
	ids_msg.terminate_connection.remote_port = remote_port
	ids_msg.terminate_connection.address_family = address_family
	ids_msg_bytes = ids_msg.SerializeToString()
	len_hex = bytes.fromhex("{:04x}".format(ids_msg.ByteSize()))  # Finding hex_length of ids_msg
	ids_msg_decision = len_hex + ids_msg_bytes  # Final decision message wrapper
	sock.send(ids_msg_decision)
	open_fd_remove(event.remote_address,remote_port,address_family)
	print("IDS Terminated ____________________________")
	return

def decision_allow(event):
	ids_msg = nstp_v2_pb2.IDSMessage()
	ids_msg.decision.event_id = event.event_id
	ids_msg.decision.allow = True
	ids_msg_bytes = ids_msg.SerializeToString()
	len_hex = bytes.fromhex("{:04x}".format(ids_msg.ByteSize()))    #Finding hex_length of ids_msg
	ids_msg_decision = len_hex + ids_msg_bytes                     	#Final decision message wrapper
	sock.send(ids_msg_decision)
	print("IDS Allowed____________________________")
	return

def iterative_terminator(event):
	terminating_list = []
	for address in open_fd:
		if address[0] == event.remote_address:
			terminating_list.append((address[1],address[2]))
	for termination_values in terminating_list:
		terminator(event,termination_values[0],termination_values[1])
	return

def decision_deny(event):
	ids_msg = nstp_v2_pb2.IDSMessage()
	ids_msg.decision.event_id = event.event_id
	ids_msg.decision.allow = False
	ids_msg_bytes = ids_msg.SerializeToString()
	len_hex = bytes.fromhex("{:04x}".format(ids_msg.ByteSize()))    #Finding hex_length of ids_msg
	ids_msg_decision = len_hex + ids_msg_bytes                     	#Final decision message wrapper
	add_to_blacklist_response = add_to_blacklist(event.remote_address)
	sock.send(ids_msg_decision)
	if(add_to_blacklist_response == 1):
		terminator(event,event.remote_port,event.address_family)
		return
	try:
		start_new_thread(iterative_terminator,(event,))
	except:
		print("Some problem with starting the thread.")
	return

def event_handler(event):
	blacklist_checker_response = blacklist_checker(event.remote_address)
	if blacklist_checker_response:
		decision_deny(event)
		return
	if event.client_to_server:
		if event.WhichOneof('event') == "connection_established":
				open_fd_response = open_fd_add(event)
				if open_fd_response:
					decision_deny(event)
					return
				threshold_checker_response = threshold_checker(event.remote_address)
				if threshold_checker_response:
					decision_deny(event)
					return
				decision_allow(event)
				return
		threshold_checker_response = threshold_checker(event.remote_address)
		if threshold_checker_response:
			decision_deny(event)
			return
		checks_response = perform_checks(event)
		if checks_response == 1:
				decision_allow(event)          #Just for now
				return
		elif checks_response == 0:
				print("FHHHHHHHHHHHH")
				decision_deny(event)
				return
	if event.WhichOneof('event') == "connection_terminated":
		open_fd_remove(event.remote_address,event.remote_port,event.address_family)
	decision_allow(event)
	return

def Main():
	server_address = '/tmp/nstp_ids.socket'
	try:
		sock.connect(server_address)
	except socket.error as msg:
		print(msg)
		sys.exit(1)
	ids_alert = nstp_v2_pb2.IDSMessage()  #Getting IDSMessage object from it's structure from protospec i.e nstp_v2_pb2
	try:
		while True:
			data = sock.recv(4096)
			if data:
				l = hex(data[0])+format(data[1],'x')     #Combine the lengths
				length_key = int(l,0)
				if len(data) == length_key + 2:
					ids_alert.ParseFromString(data[2:len(data)])
					print("IDS Alert : {}".format(ids_alert))
					event_handler(ids_alert.event)
					print(open_fd)
					#time.sleep(0.05)                #Do not forget to remove this
				else:
					decision_deny(ids_alert.event)
					print("Something wrong with length")

	except:
		print(open_fd)
		print(threshold_tracker)
		sock.close()
if __name__ == '__main__':
	Main()



	#except:
	#	print("IDS Failure Alert!!!")
