#!/usr/bin/env python2.7
# -*- coding:utf-8 -*-


import os, time, threading, json
import socket, struct
from datetime import datetime
from scapy.all import *
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from argparse import ArgumentParser

ip2latlon = {}
traffic_list = []
max_size = 5000
cur_idx = -1

sniff_iface = 'eth0'


class MyHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		root_dir = './tmap/'
		try:
			content_type = 'text/html'
			if self.path.endswith('.js'):
				content_type = 'application/javascript'
			elif self.path.endswith('.css'):
				content_type = 'text/css'

			if '..' in self.path:
				self.send_error(400, 'Bad Request')
			elif '/get_traffic' in self.path:
				self.send_response(200)
				self.send_header('Content-Type', content_type)
				self.end_headers()

				global traffic_list
				global max_size
				global cur_idx

				t = float(self.path.split('t=')[1])
				
				idx = cur_idx
				res_list = []
				if t == 0.0:
					if idx != -1:
						res_list.append(traffic_list[idx])
				elif t < traffic_list[idx]['time']:
					res_list.append(traffic_list[idx])

					if len(traffic_list) < max_size:
						for i in range(idx-1, -1, -1):
							if t < traffic_list[i]['time']:
								res_list.insert(0, traffic_list[i])
							else:
								break
					else:
						i = idx - 1
						while i >= 0:
							if t < traffic_list[i]['time']:
								res_list.insert(0, traffic_list[i])
							else:
								break
							i = i - 1

						j = len(traffic_list) - 1
						while i == -1 and j >= 0:
							if t < traffic_list[j]['time']:
								res_list.insert(0, traffic_list[j])
							else:
								break
							j = j - 1

				self.wfile.write(json.dumps(res_list))
			elif self.path.endswith('/map.js'):
				f = open(root_dir + self.path)
				self.send_response(200)
				self.send_header('Content-Type', content_type)
				self.end_headers()
				js_text = f.read()
				js_text = js_text.replace('[TMAP_ADDR]', self.server.server_name)
				js_text = js_text.replace('[TMAP_PORT]', str(self.server.server_port))
				self.wfile.write(js_text)
				f.close()
			else:
				f = open(root_dir + self.path)
				self.send_response(200)
				self.send_header('Content-Type', content_type)
				self.end_headers()
				self.wfile.write(f.read())
				f.close()
		except Exception as e:
			self.send_error(404, 'File Not Found: %s' % self.path)


def read_jsonfile(filepath):
    try:
        with open(filepath, 'r') as f:
            data = f.read()
        return json.loads(data)
    except Exception as e:
    	print(str(e))
        return None


def get_ip(packet):
	t = packet.time
	src_ip = packet[IP].src
	dst_ip = packet[IP].dst
	headers = '\n'.join(packet.sprintf("{Raw:%Raw.load%}").split(r'\r\n\r\n')[0].split(r"\r\n"))
	print(src_ip, '-->', dst_ip)

	global ip2latlon

	v1 = int(socket.inet_aton(src_ip).encode('hex'), 16) & (0xFFFFFFFF << (32 - 20))
	v2 = int(socket.inet_aton(dst_ip).encode('hex'), 16) & (0xFFFFFFFF << (32 - 20))
	src_ip_1 = socket.inet_ntoa(struct.pack("!I", v1))
	dst_ip_1 = socket.inet_ntoa(struct.pack("!I", v2))

	# {"country_code":"", "city":"", "lat":"", "lon":"", "ip":"", "key":""}
	src_obj = ip2latlon[src_ip_1]
	src_obj['ip'] = src_ip
	src_obj['key'] = 'src'

	dst_obj = ip2latlon[dst_ip_1]
	dst_obj['ip'] = dst_ip
	dst_obj['key'] = 'dst'

	traffic = { "desc": 'http GET request', "level": 0, "color_idx": 1, "time": t, "dst": src_obj, "src": dst_obj }

	global traffic_list
	global max_size
	global cur_idx

	if len(traffic_list) < max_size:
		traffic_list.append(traffic)
		cur_idx += 1
	else:
		if cur_idx == len(traffic_list) - 1:
			traffic_list[0] = traffic
			cur_idx = 0
		else:
			traffic_list[cur_idx+1] = traffic
			cur_idx += 1


def http_sniffer():
	global sniff_iface
	sniff(iface=sniff_iface, prn=get_ip, lfilter=lambda p: "GET " in str(p), filter="tcp")


if __name__ == '__main__':
	parser = ArgumentParser(description='tmap')
	parser.add_argument('--addr', default='127.0.0.1', help='the tmap server addr')
	parser.add_argument('--port', default=8888, type=int, help='the tmap server port')
	parser.add_argument('--iface', default='eth0', help='the sniff interface')
	args = parser.parse_args()
	tmap_addr = args.addr
	tmap_port = args.port
	sniff_iface = args.iface
	
	ip2latlon = read_jsonfile('./data/ip2latlon.json')

	try:
		sniffer_thread = threading.Thread(target=http_sniffer, args=())
		sniffer_thread.start()

		server = HTTPServer((tmap_addr, tmap_port), MyHandler)
		print('start httpserver on %s:%d' %(tmap_addr, tmap_port))
		server.serve_forever()
	except Exception as e:
		server.socket.close()
