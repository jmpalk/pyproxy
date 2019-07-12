# pyproxy
A simple Python 3 SOCKS5 proxy

Opens a SOCKS5 proxy on 0.0.0.0:9999

usage: pyproxy.py [-h] [-a ALLOWED_IP] [-p PORT] [-b BIND_IP]

Start a simple SOCKS5 proxy

optional arguments:
  -h, --help            show this help message and exit
  -a ALLOWED_IP, --allowed_ip ALLOWED_IP
                        IP address allowed to connect to the proxy. Defaults
                        to 127.0.0.1
  -p PORT, --port PORT  Port to listen on
  -b BIND_IP, --bind_ip BIND_IP
                        Listening IP address. Defaults to 0.0.0.0 (all
                        interfaces).

