#!/usr/bin/env python3
"""Check the direct relay is bound to a physical interface, without changing routes."""
import csv
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
interface=sys.argv[1] if len(sys.argv)>1 else 'en0'
token=os.urandom(16).hex(); env=os.environ.copy(); env['NAPTD_RELAY_TOKEN']=token
proc=subprocess.Popen([str(ROOT/'socks_gateway'),'direct',interface],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1,env=env)
try:
    ready,_,_=select.select([proc.stdout],[],[],8)
    if not ready: raise RuntimeError('direct gateway did not start')
    line=proc.stdout.readline().strip()
    if not line.startswith('gateway_ready:'): raise RuntimeError('direct gateway failed: '+line+' '+proc.stderr.read()[:200])
    _,tcp_port,udp_port=line.split(':'); tcp_port=int(tcp_port); udp_port=int(udp_port)
    # Keep a UDP flow open while checking the kernel's actual egress interface.
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as hold:
        hold.sendto(b'UDP1'+token.encode()+socket.inet_aton('1.1.1.1')+struct.pack('!H',53)+b'probe',('127.0.0.1',udp_port)); time.sleep(1)
        result=subprocess.run(['/usr/bin/nettop','-p',str(proc.pid),'-L','1','-x','-n'],capture_output=True,text=True,timeout=15)
        rows=list(csv.reader(result.stdout.splitlines()))
        matches=[r for r in rows if len(r)>3 and r[1].startswith('udp4 ') and '1.1.1.1:53' in r[1]]
        assert matches and all(r[2]==interface for r in matches), 'bound connection did not use the selected interface'
    # Two datagrams in one flow must reach an echo server from the same source port.
    address=matches[0][1].split(' ',1)[1].split(':',1)[0]
    seen=[]
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
        server.bind((address,0)); server.settimeout(8)
        def echo():
            for _ in range(2):
                payload,peer=server.recvfrom(2048); seen.append(peer[1]); server.sendto(payload,peer)
        thread=threading.Thread(target=echo,daemon=True); thread.start()
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
            client.settimeout(8); header=b'UDP1'+token.encode()+socket.inet_aton(address)+struct.pack('!H',server.getsockname()[1])
            for data in (b'first',b'second'):
                client.sendto(header+data,('127.0.0.1',udp_port)); reply,_=client.recvfrom(2048)
                assert reply==header+data
        thread.join(timeout=3); assert len(seen)==2 and seen[0]==seen[1]
    print('Direct gateway: UDP used selected physical interface; flow and source port remained stable')
finally:
    proc.terminate()
    try: proc.wait(timeout=3)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=3)
