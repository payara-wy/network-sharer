#!/usr/bin/env python3
"""Probe the gateway through an existing local SOCKS5 service; records no content."""
import ipaddress
import os
from pathlib import Path
import select
import socket
import ssl
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
proxy_port=int(sys.argv[1]) if len(sys.argv)>1 else 1082
token=os.urandom(16).hex().encode()

def readn(sock,n):
    out=b''
    while len(out)<n:
        chunk=sock.recv(n-len(out))
        if not chunk: raise RuntimeError('connection closed')
        out+=chunk
    return out

def first_ipv4(data):
    if len(data)<12: raise ValueError('short DNS reply')
    qd,an=struct.unpack('!HH',data[4:8]); off=12
    def skip(i):
        while i<len(data):
            n=data[i]; i+=1
            if n&0xc0==0xc0: return i+1
            if n==0: return i
            i+=n
        raise ValueError('invalid name')
    for _ in range(qd): off=skip(off)+4
    for _ in range(an):
        off=skip(off); typ,cls,_,n=struct.unpack('!HHIH',data[off:off+10]); off+=10
        if typ==1 and cls==1 and n==4: return socket.inet_ntoa(data[off:off+4])
        off+=n
    raise ValueError('no IPv4 answer')

env=os.environ.copy(); env['NAPTD_RELAY_TOKEN']=token.decode()
proc=subprocess.Popen([str(ROOT/'socks_gateway'),'socks5',str(proxy_port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1,env=env)
try:
    ready,_,_=select.select([proc.stdout],[],[],8)
    if not ready: raise RuntimeError('gateway did not start')
    line=proc.stdout.readline().strip()
    if not line.startswith('gateway_ready:'): raise RuntimeError('gateway error: '+line+' '+proc.stderr.read()[:200])
    _,tcp_port,dns_port=line.split(':'); tcp_port=int(tcp_port); dns_port=int(dns_port)
    name='example.com'; qid=os.urandom(2)
    query=qid+struct.pack('!HHHHH',0x0100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',1,1)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns:
        dns.settimeout(10); dns.sendto(b'DNS1'+token+query,('127.0.0.1',dns_port)); response,_=dns.recvfrom(4096)
        assert response.startswith(b'DNS1'+token); response=response[36:]
    assert response[:2]==qid and response[3]&15==0
    address=str(ipaddress.IPv4Address(first_ipv4(response)))
    with socket.create_connection(('127.0.0.1',tcp_port),timeout=5) as raw:
        raw.settimeout(12); raw.sendall(b'NAT1'+token+socket.inet_aton(address)+struct.pack('!H',443))
        with ssl.create_default_context().wrap_socket(raw,server_hostname=name) as secure:
            secure.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
            response=secure.recv(1024)
    assert response.startswith(b'HTTP/1.1 200') or response.startswith(b'HTTP/2 200')
    with socket.create_connection(('127.0.0.1',tcp_port),timeout=4) as bad:
        bad.settimeout(5); bad.sendall(b'NAT1'+b'0'*32+socket.inet_aton(address)+struct.pack('!H',443))
        assert bad.recv(1)==b''
    print('SOCKS5 gateway: DNS over TCP, verified HTTPS, invalid token rejection passed')
finally:
    proc.terminate()
    try: proc.wait(timeout=3)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=3)
