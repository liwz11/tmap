#!/usr/bin/env python2.7
# -*- coding:utf-8 -*-


import os, time, threading, json, subprocess
import socket, struct
from datetime import datetime
from scapy.all import *
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from argparse import ArgumentParser


traffic_list = []
max_size = 500
cur_idx = -1

performance = {'bw_unit':'Mbps', 'ibw':0, 'obw':0, 'conn':0}


class MyHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		root_dir = './tmap/'
		temp = self.path.split('?')
		path = temp[0]
		pram = ''
		if len(temp) > 1:
			pram = temp[1]
		try:
			content_type = 'text/html'
			if path.endswith('.js'):
				content_type = 'application/javascript'
			elif path.endswith('.css'):
				content_type = 'text/css'

			if '..' in path:
				self.send_error(400, 'Bad Request')
			elif path == '/get_traffic':
				self.send_response(200)
				self.send_header('Content-Type', content_type)
				self.end_headers()

				global traffic_list
				global max_size
				global cur_idx
				
				t = 999999999
				temp = pram.split('t=')
				if len(temp) > 1:
					t = float(temp[1])
				
				idx = cur_idx
				res_list = []
				if t == 0.0:
					if idx != -1:
						res_list.append(traffic_list[idx])
				elif t < traffic_list[idx]['time']:
					res_list.append(traffic_list[idx])

					if len(traffic_list) < max_size:
						for i in range(idx-1, -1, -1):
							if t >= traffic_list[i]['time'] or len(res_list) >= 50:
								print('cur - end - res', idx, i, len(res_list))
								break
							res_list.insert(0, traffic_list[i])
					else:
						i = idx - 1
						while i >= 0:
							if t >= traffic_list[i]['time'] or len(res_list) >= 50:
								print('cur - end - res', idx, i, len(res_list))
								break
							res_list.insert(0, traffic_list[i])
							
							i = i - 1

						j = len(traffic_list) - 1
						while i == -1 and j >= 0:
							if t >= traffic_list[j]['time'] or len(res_list) >= 50:
								print('cur - end - res', idx, j, len(res_list))
								break
							res_list.insert(0, traffic_list[j])
							
							j = j - 1
				print(performance)
				self.wfile.write(json.dumps(res_list))
			elif path == '/map.js':
				f = open(root_dir + path)
				self.send_response(200)
				self.send_header('Content-Type', content_type)
				self.end_headers()

				global tmap_domain
				global tmap_addr
				global tmap_port
				global interval
				global timeout

				js_text = f.read()
				js_text = js_text.replace('[TMAP_DOMAIN]', tmap_domain)
				js_text = js_text.replace('[TMAP_ADDR]', tmap_addr)
				js_text = js_text.replace('[TMAP_PORT]', str(tmap_port))
				js_text = js_text.replace('[INTERVAL]', str(interval))
				js_text = js_text.replace('[TIMEOUT]', str(timeout))
				self.wfile.write(js_text)
				f.close()
			else:
				f = open(root_dir + path)
				self.send_response(200)
				self.send_header('Content-Type', content_type)
				self.end_headers()
				self.wfile.write(f.read())
				f.close()
		except Exception as e:
			print('Error:', str(e))
			if 'Broken pipe' not in str(e):
				self.send_error(404, 'File Not Found: %s' % path)
			else:
				print('Debug: Connection reset by peer.')


# 字典极其消耗内存
def read_jsonfile(filepath):
    try:
        with open(filepath, 'r') as f:
            data = f.read()
        return json.loads(data)
    except Exception as e:
        print('Error: [read_jsonfile] ' + str(e))
        return None


def popen_command(command):
    try:
        p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = p.communicate()
        return output.strip()
    except Exception as e:
        print('Error: [popen_command] ' + str(e))
        print('Command: ' + command)
        return None


def get_json_obj(filepath, key):
    try:
        res = popen_command("cat " + filepath + " | grep '\"" + key + "\"'")

        for i in range(0, len(res)):
            if res[i] == '{':
                start = i
            if res[i] == '}':
                end = i
        return json.loads(res[start:end+1])
    except Exception as e:
        print('Error: [get_json_obj] ' + str(e))
        return None


def get_ip(packet):
	t = packet.time
	src_ip = packet[IP].src
	dst_ip = packet[IP].dst
	
	global dst_obj

	if dst_ip == dst_obj['ip']:
		ip_int = int(socket.inet_aton(src_ip).encode('hex'), 16) & (0xFFFFFFFF << (32 - 20))
		src_ip_1 = socket.inet_ntoa(struct.pack("!I", ip_int))
		src_obj = get_json_obj('./data/ip2latlon.json', src_ip_1)
		src_obj['ip'] = src_ip
		src_obj['key'] = 'src-' + str(t) # 这里的key非常重要，一定要保证都不一样
		#print(src_obj)

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


def network_monitor():
	print('network_monitor - [start]')

	global interface
	global tmap_addr

	sniff(iface=interface, prn=get_ip, filter="dst host %s and tcp" % tmap_addr)


def performance_monitor():
	print('performance_monitor - [start]')

	global interface
	global tmap_addr
	global performance

	ibound_cmd = "ifconfig " + interface + " | grep 'bytes' | cut -d ':' -f2 | cut -d ' ' -f1"
	obound_cmd = "ifconfig " + interface + " | grep 'bytes' | cut -d ':' -f3 | cut -d ' ' -f1"
	conn_cmd   = "netstat -n | awk '/" + tmap_addr + ":80/ {++S[$NF]} END {for(a in S) print a, S[a]}' | grep 'ESTABLISHED' | cut -d ' ' -f2"

	while True:
		t1 = time.time()
		ibound_prev = int(popen_command(ibound_cmd))
		obound_prev = int(popen_command(obound_cmd))

		time.sleep(1)

		t2 = time.time()
		ibound_curr = int(popen_command(ibound_cmd))
		obound_curr = int(popen_command(obound_cmd))

		res = popen_command(conn_cmd)
		conn = 0
		if res != '':
			conn = int(res)

		bw_unit = 'Kbps'
		ibw = (ibound_curr - ibound_prev) * 8 / (t2 - t1) / 1000 #Kbps
		obw = (obound_curr - obound_prev) * 8 / (t2 - t1) / 1000 #Kbps

		if ibw > 1000 or obw > 1000:
			bw_unit = 'Mbps'
			ibw = ibw / 1000
			obw = obw / 1000
		
		if ibw > 1:
			ibw = '%.2f' % ibw
		else:
			ibw = '%.2g' % ibw
		if obw > 1:
			obw = '%.2f' % obw
		else:
			obw = '%.2g' % obw

		performance['ibw'] = performance = {'bw_unit':bw_unit, 'ibw':ibw, 'obw':obw, 'conn':conn}


if __name__ == '__main__':
	parser = ArgumentParser(description='tmap')
	parser.add_argument('--domain', default='-', help='the tmap server domain')
	parser.add_argument('--addr', default='127.0.0.1', help='the tmap server addr')
	parser.add_argument('--port', default=8888, type=int, help='the tmap server port')
	parser.add_argument('--iface', default='eth0', help='the sniff interface')
	parser.add_argument('--interval', default=1, type=int, help='the interval to get traffic in map.js')
	parser.add_argument('--timeout', default=5, type=int, help='the timeout to get traffic in map.js')
	args = parser.parse_args()
	tmap_domain = args.domain
	tmap_addr = args.addr
	tmap_port = args.port
	interface = args.iface
	interval = args.interval
	timeout = args.timeout

	if tmap_domain == '-':
		tmap_domain = tmap_addr

	# 字典极其消耗内存
	'''
	print('read file - ip2latlon.json [start]')
	ip2latlon = read_jsonfile('./data/ip2latlon.json')
	print('read file - ip2latlon.json [finish]')
	print(ip2latlon['255.255.240.0'])
	'''

	ip_int = int(socket.inet_aton(tmap_addr).encode('hex'), 16) & (0xFFFFFFFF << (32 - 20))
	tmap_addr_1 = socket.inet_ntoa(struct.pack("!I", ip_int))
	dst_obj = get_json_obj('./data/ip2latlon.json', tmap_addr_1)
	dst_obj['ip'] = tmap_addr
	dst_obj['key'] = 'dst'

	try:
		network_monitor_thread = threading.Thread(target=network_monitor, args=())
		network_monitor_thread.setDaemon(True) # 一旦主线程执行结束，子线程被终止执行
		network_monitor_thread.start()

		performance_monitor_thread = threading.Thread(target=performance_monitor, args=())
		performance_monitor_thread.setDaemon(True)
		performance_monitor_thread.start()

		server = HTTPServer((tmap_addr, tmap_port), MyHandler)
		print('httpserver on %s:%d' %(tmap_addr, tmap_port), '[start]')
		server.serve_forever()
	except Exception as e:
		server.socket.close()
