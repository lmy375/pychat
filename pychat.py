# coding:utf-8

import socket
import json
import thread
import logging
import argparse
import time
import Queue
import random
import urllib

import SimpleHTTPServer
import webbrowser

def log_init(level=logging.DEBUG):
	console_log = logging.StreamHandler()
	console_log.setFormatter(logging.Formatter('[%(asctime)s] %(message)s', "%H:%M:%S"))
	log = logging.getLogger("pychat")
	log.addHandler(console_log) # Add console logger
	log.setLevel(level)
	return log

CHAT_TYPE_HELLO = 1
CHAT_TYPE_MSG = 2
CHAT_TYPE_BYE = 3

CHAT_HOST = '0.0.0.0'
CHAT_PORT = 8888
CHAT_HELLO_TIME = 3


class PyChat(object):
	"""docstring for PyChatServer"""
	def __init__(self, name, port=CHAT_PORT, hello_time =CHAT_HELLO_TIME):
		self.name = name
		
		# port to recv data.
		self.port = port

		# hello 3 times when starts.
		self.hello_time = hello_time

		# use this to identify user.
		self.id = random.randint(1,0xffffffff) 

		self.server = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		self.server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		self.server.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
		self.server.bind((CHAT_HOST, self.port))

		#self.client = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		#self.client.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
		self.client = self.server  # in fact we can use same socket.

		self.peers = {} # {id:ip}
		self.queue = Queue.Queue()

	def _client_send(self, data, ip='255.255.255.255'):
		port = self.port
		if type(data) is dict:
			data = json.dumps(data) # so we can handle json here.
		log.debug('SEND: (%s:%s) %s' %(ip, port, data))
		self.client.sendto(data, (ip, port))

	def _new_packet(self, packet_type):
		s = {}
		s['type'] = packet_type
		s['name'] = self.name
		s['time'] = time.ctime()
		s['id'] = self.id
		return s

	def _new_hello_packet(self):
		s = self._new_packet(CHAT_TYPE_HELLO)
		return s

	def send_hello(self, ip='255.255.255.255'):
		hello_packet = self._new_hello_packet()
		self._client_send(hello_packet, ip)
		return hello_packet


	def _new_msg_packet(self, msg):
		s = self._new_packet(CHAT_TYPE_MSG)
		s['msg'] = msg
		return s

	def send_msg(self,msg, id=None):		
		msg_packet = self._new_msg_packet(msg)
		log.debug('id: %s peers:%s'%(id, self.peers))
		if id and id in self.peers:
			ip = self.peers[id]
			msg_packet['to'] = id
			log.debug('To %d %s'%(id, ip))
		else:
			ip = '255.255.255.255'
		self._client_send(msg_packet, ip)
		return msg_packet


	def _new_bye_packet(self):
		s = self._new_packet(CHAT_TYPE_BYE)
		return s

	def send_bye(self, ip='255.255.255.255'):
		bye_packet = self._new_bye_packet()
		self._client_send(bye_packet, ip)
		return bye_packet


	def server_loop(self):
		while True:
			try:
				data, addr =  self.server.recvfrom(1024)				
				ip, port = addr
				log.debug("RECV: (%s:%s) %s" % (ip, port, data))

				# Parse json first. 
				packet = json.loads(data)

				# skip packets we send to ourselves.
				if packet['id'] == self.id :
					continue
				
				# skip packets not send to us.
				if 'to' in packet.keys() and packet['to']!= self.id:
					continue

				# If json parse error, peers won't be added.
				if packet['id'] not in self.peers:
					# All packets can lead to peer adding. 
					self.peers[packet['id']] = ip
					
					# we add a peer whatever kind of packet we receive.
					fake_packet = packet.copy()
					fake_packet['type'] = CHAT_TYPE_HELLO
					self.queue.put(fake_packet)

					log.info('Peer added: %s' % packet['id'] )

					# If we get a packet from new peer, say hello to it to let it know us.
					# Broadcast causes saying hello to ourselves, but doesn't really matter. 
					self.send_hello(ip)



				if packet['type'] == CHAT_TYPE_MSG:
					log.info('%s(%s) says: %s'% (packet['name'], packet['id'], packet['msg']) )

					# for externel ui.
					self.queue.put(packet)


				if packet['type'] == CHAT_TYPE_BYE:
					self.peers.pop(packet['id'])
					log.info('Peer removed: %s' % packet['id'])

					# for externel ui.
					self.queue.put(packet)

					#self._client_send(self._new_hello_packet())
			except Exception,e:
				log.error("server loop error: %s" % e)

	def start(self):
		thread.start_new(self.server_loop, ())

	def find_peers(self):
		for i in range(self.hello_time):
			self.send_hello()


WEB_HOST = 'localhost'
WEB_PORT = 8890
WEB_LOG  = False
# for web ui
class PyChatHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

	def log_message(self, format, *args):
		if WEB_LOG:
			SimpleHTTPServer.SimpleHTTPRequestHandler.log_message(self, format, *args)

	def peek_msg(self):
		queue = chat.queue
		l = []
		while True:
			if queue.empty():
				break
			l.append(queue.get())
		return l
	
	def _post_args(self, post_str):
		post_str = urllib.unquote_plus(post_str)
		d = {}
		for arg in post_str.split('&'):
			key, value = arg.split('=')
			d[key] = value
		return d

	def _send_text(self, content):
		self.send_response(200)
		self.send_header('Content-type', 'text/plain')
		self.send_header('Content-Length', len(content))
		self.end_headers()
		self.wfile.write(content)		

	def do_POST(self):
		if self.path == '/peek':
			l = self.peek_msg()
			d = {}
			d['n'] = len(l)
			d['l'] = l
			content = json.dumps(d)
			self._send_text(content)

			#log.debug('WEB /peek -> %s' % content)


		if self.path == '/send':
			length = int(self.headers.getheader('content-length'))  
			post_str = self.rfile.read(length)
			post_args = self._post_args(post_str)

			log.debug('WEB /send %s' % post_str)

			msg = post_args['msg']
			if 'to' in post_args.keys():
				to_id = int(post_args['to'])
				log.debug('Messaget to %s' % to_id )
				packet = chat.send_msg(msg, to_id)
			else:
				packet = chat.send_msg(msg)

			packet['success'] = True

			content = json.dumps(packet)
			self._send_text(content)


def web_ui(host, port ):
	s = SimpleHTTPServer.BaseHTTPServer.HTTPServer((host,port), PyChatHandler)
	s.serve_forever()


def print_msg(queue):
	while True:
		packet = queue.get()
		if packet['type'] == CHAT_TYPE_HELLO:
			print '[%s (%s) -%s] Enter PyChat.' %(
				packet['name'],
				packet['id'],
				packet['time'])

		if packet['type'] == CHAT_TYPE_MSG:
			print '[%s (%s) -%s] : %s' % (
				packet['name'],
				packet['id'],
				packet['time'],
				packet['msg'])

		if packet['type'] == CHAT_TYPE_BYE:
			print '[%s (%s) -%s] Exit PyChat.' %(
				packet['name'],
				packet['id'],
				packet['time'])
			

def pychat_cmd():
	parser = argparse.ArgumentParser()
	parser.add_argument('-v', '--verbose', action='count', default=0, help="-v for info, -vv for debug")
	parser.add_argument('-n', '--name', default='PyChatUser', help="nickname in chat room, default PyChatUser")
	parser.add_argument('-p', '--port',type=int, default=CHAT_PORT, help='pychat port to recevive data, default %s' % CHAT_PORT )
	parser.add_argument('-t', '--hello_time', type=int, default=CHAT_HELLO_TIME, help='times to find peer in LAN when starts, default %s' % CHAT_HELLO_TIME)

	parser.add_argument('-w', '--web', action='store_true', help='start web UI.')
	parser.add_argument('--web_host', default=WEB_HOST, help = 'web UI host, default %s' % WEB_HOST)
	parser.add_argument('--web_port',type=int, default= WEB_PORT, help = 'web UI port, default %s' % WEB_PORT)

	args = parser.parse_args()
	
	if args.verbose >=2:
		log_level = logging.DEBUG
	elif args.verbose >=1:
		log_level = logging.INFO
	else:
		log_level = logging.ERROR

	global log
	log = log_init(log_level)

	# "chat" global variable will be used in web ui handler
	global chat
	chat = PyChat(args.name, args.port, args.hello_time) 
	chat.start()

	log.info('Your PyChat ID: %s' % chat.id)

	if args.web:
		thread.start_new(web_ui, (args.web_host, args.web_port))
		webbrowser.open('http://%s:%s/' %(args.web_host, args.web_port))
	else:
		thread.start_new(print_msg, (chat.queue,))

	chat.find_peers()

	while True:
		msg = raw_input('')
		if msg == 'exit': break
		if len(msg):
			chat.send_msg(msg)

	chat.send_bye()



if __name__ == '__main__':
	pychat_cmd()