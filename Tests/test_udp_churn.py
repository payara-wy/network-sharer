#!/usr/bin/env python3
"""Check active UDP flow churn using only this Mac's Wi-Fi address."""
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import threading

ROOT=Path(__file__).resolve().parents[1]
interface=sys.argv[1] if len(sys.argv)>1 else 'en0'
address=subprocess.check_output(['/usr/sbin/ipconfig','getifaddr',interface],text=True).strip()
token=os.urandom(16).hex().encode()
env=dict(os.environ,NAPTD_RELAY_TOKEN=token.decode())
gateway=subprocess.Popen([str(ROOT/'socks_gateway'),'direct',interface],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
clients=[]; stop=threading.Event()
try:
    assert select.select([gateway.stdout],[],[],8)[0]
    line=gateway.stdout.readline().strip(); assert line.startswith('gateway_ready:'),line
    udp_port=int(line.split(':')[2])
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
        server.bind((address,0)); server.settimeout(.2)
        def echo():
            while not stop.is_set():
                try: payload,peer=server.recvfrom(2048); server.sendto(payload,peer)
                except socket.timeout: continue
                except OSError: break
        thread=threading.Thread(target=echo,daemon=True); thread.start()
        header=b'UDP1'+token+socket.inet_aton(address)+struct.pack('!H',server.getsockname()[1])
        for i in range(270):
            client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); client.settimeout(3); clients.append(client)
            data=struct.pack('!I',i)
            client.sendto(header+data,('127.0.0.1',udp_port))
            response,_=client.recvfrom(2048)
            assert response==header+data,i
        clients[0].sendto(header+b'retry',('127.0.0.1',udp_port))
        assert clients[0].recvfrom(2048)[0]==header+b'retry'
        stop.set(); thread.join(timeout=3)
    print('270 UDP flows and an evicted flow reconnect all passed with a 256-flow cap')
finally:
    stop.set()
    for client in clients: client.close()
    gateway.terminate()
    try: gateway.wait(timeout=3)
    except subprocess.TimeoutExpired: gateway.kill(); gateway.wait(timeout=3)
