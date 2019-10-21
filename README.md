# tmap
just like norse attack map

# Usage

```
usage: server.py [-h] [--domain DOMAIN] [--addr ADDR] [--port PORT]
                 [--iface IFACE] [--interval INTERVAL] [--timeout TIMEOUT]

tmap

optional arguments:
  -h, --help           show this help message and exit
  --domain DOMAIN      the tmap server domain, default '-'
  --addr ADDR          the tmap server addr, default '127.0.0.1'
  --port PORT          the tmap server port, default 8888
  --iface IFACE        the sniff interface, default 'eth0'
  --interval INTERVAL  the interval to get traffic in map.js, default 1
  --timeout TIMEOUT    the timeout to get traffic in map.js, default 5
  
examples:

sudo python server.py --iface ens33 --addr 192.168.47.136 --port 8888
--> http://192.168.47.136:8888/index.html
sudo python server.py --iface ens33 --addr 192.168.47.136 --port 8888 --domain example.com
--> http://example.com:8888/index.html
```

