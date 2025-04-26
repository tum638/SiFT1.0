#python3

import socket
import PublicKeyEncryption
from Crypto.Random import get_random_bytes

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = False
		# --------- CONSTANTS ------------
		self.version_major = 1
		self.version_minor = 0
		self.msg_hdr_ver = b'\x00\x10'
		self.msg_hdr_sqn = b'\x00\x00'
		self.msg_hdr_rsv = b'\x00\x00'
		self.msg_hdr_rnd = b'\x00\x00\x00\x00\x00\x00'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rsv = 2
		self.size_msg_hdr_rnd = 6
		self.sym_key_length = 256
		self.mac_length = 16
		self.perm_sym_key = None
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket
		self.enc = PublicKeyEncryption.Encryption()
		
	
	def get_perm_sym_key(self):
		if not self.perm_sym_key:
			raise SiFT_MTP_Error("Permanent Symmetric Key has not been set")
		return self.perm_sym_key
	
	def set_perm_sym_key(self, perm_sym_key):
		self.perm_sym_key = perm_sym_key

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'] = msg_hdr[i:i+self.size_msg_hdr_rsv]
		return parsed_msg_hdr

	def parse_msg_body(self, msg_body, login_req=False):
		parsed_msg_body, i = {}, len(msg_body)
		if login_req:
			parsed_msg_body['etk'], i = msg_body[i-self.sym_key_length:i], i-self.sym_key_length
		parsed_msg_body['mac'], i = msg_body[i-self.mac_length:i], i-self.mac_length
		parsed_msg_body['epd'] = msg_body[:i]	
		return parsed_msg_body


	# receives n bytes from the peer socket
	def receive_bytes(self, n):

		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received


	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):

		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')
		
		if int.from_bytes(parsed_msg_hdr['sqn'], 'big') < int.from_bytes(self.msg_hdr_sqn, 'big'):
			raise SiFT_MTP_Error('Invalid sequence number found in message header')
		self.msg_hdr_sqn = parsed_msg_hdr['sqn']

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG 

		if len(msg_body) != msg_len - self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message body reveived')
		
		#decrypt the payload
		payload = msg_body
		if parsed_msg_hdr['typ'] == self.type_login_req:
			parsed_msg_body = self.parse_msg_body(msg_body, login_req=True)
			etk = parsed_msg_body['etk']
			try:
				tk = self.enc.decrypt_sym_key(etk)
			except ValueError:
				print('Error: decryption of AES key failed')

			mac = parsed_msg_body['mac']
			epd = parsed_msg_body['epd']

			payload = self.enc.decrypt_epd(
							epd,
							msg_hdr,
							parsed_msg_hdr['sqn'],
							parsed_msg_hdr['rnd'], 
							tk, 
							mac
							)
		# TODO: add else statement for other types
			
		return parsed_msg_hdr['typ'], payload


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		
		# build message
		msg_size = self.size_msg_hdr + len(msg_payload) + self.mac_length
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')

		#increment sequence number
		sequence_number = int.from_bytes(self.msg_hdr_sqn, byteorder='big') + 1
		self.msg_hdr_sqn = sequence_number.to_bytes(self.size_msg_hdr_sqn, byteorder='big')
        
		#generate random bytes
		self.msg_hdr_rnd = get_random_bytes(self.size_msg_hdr_rnd)

		# build message header
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + self.msg_hdr_sqn + self.msg_hdr_rnd + self.msg_hdr_rsv
        
		# add encryption
		info = self.enc.encrypt(msg_payload, msg_hdr, self.msg_hdr_sqn, self.msg_hdr_rnd)

		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_payload)) + '): ')
			print(msg_payload.hex())
			print('------------------------------------------')
		# DEBUG 

		if msg_type == self.type_login_req:
			bytes_to_send = msg_hdr + info['epd'] + info['mac'] + info['aes_key']
		else:
			bytes_to_send = msg_hdr + info['epd'] + info['mac']

		# try to send
		try:
			self.send_bytes(bytes_to_send)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)


