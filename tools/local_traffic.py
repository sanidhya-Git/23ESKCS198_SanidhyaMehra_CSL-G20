"""
local_traffic.py - Creates test traffic on THIS computer only (127.0.0.1),
so the sniffer can be demonstrated on the loopback interface without
touching any other system.

  python tools/local_traffic.py web    # HTTP requests to a local web server
  python tools/local_traffic.py udp    # UDP datagrams to local ports
  python tools/local_traffic.py ping   # ICMP echo to 127.0.0.1 (needs admin)
  python tools/local_traffic.py scan   # TCP connect to ports 1-40 of 127.0.0.1
  python tools/local_traffic.py all

Capture with:  sudo python sniffer.py -i lo      (Linux loopback)
"""

import http.server
import socket
import sys
import threading
import time
import urllib.request

HOST = "127.0.0.1"


def web(n=3, port=8000):
    server = http.server.HTTPServer((HOST, port), http.server.SimpleHTTPRequestHandler)
    server.RequestHandlerClass.log_message = lambda *a: None      # keep output quiet
    threading.Thread(target=server.serve_forever, daemon=True).start()
    for i in range(n):
        with urllib.request.urlopen(f"http://{HOST}:{port}/?page={i}") as r:
            print(f"web: GET /?page={i} -> {r.status}")
        time.sleep(0.2)
    server.shutdown()


def udp(n=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(n):
        s.sendto(f"sensor reading {i}".encode(), (HOST, 9999))
        print(f"udp: sent datagram {i} to port 9999")
        time.sleep(0.2)
    s.close()


def ping(n=2):
    from scapy.all import ICMP, IP, sr1
    for i in range(n):
        reply = sr1(IP(dst=HOST) / ICMP(id=0x1234, seq=i), timeout=2, verbose=False)
        print(f"ping: seq={i} reply={'yes' if reply else 'no'}")


def scan(first=1, last=40):
    open_ports = []
    for port in range(first, last + 1):
        s = socket.socket()
        s.settimeout(0.2)
        if s.connect_ex((HOST, port)) == 0:
            open_ports.append(port)
        s.close()
    print(f"scan: tried ports {first}-{last} on {HOST}, open: {open_ports or 'none'}")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    actions = {"web": web, "udp": udp, "ping": ping, "scan": scan}
    for name in (actions if mode == "all" else [mode]):
        actions[name]()
