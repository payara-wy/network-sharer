#!/usr/bin/env python3
"""Exercise SOCKS5 username/password authentication with a local mock server."""
import os
from pathlib import Path
import select
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading

ROOT=Path(__file__).resolve().parents[1]
USER='test-user'.encode(); PASSWORD='test-password'.encode()
TOKEN=os.urandom(16).hex()

def readn(s,n):
    out=b''
    while len(out)<n:
        part=s.recv(n-len(out))
        if not part: raise EOFError()
        out+=part
    return out

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        s=self.request; s.settimeout(5)
        try:
            version,count=readn(s,2); methods=readn(s,count)
            if version!=5 or 2 not in methods: s.sendall(b'\x05\xff'); return
            s.sendall(b'\x05\x02')
            version,n=readn(s,2); user=readn(s,n); n=readn(s,1)[0]; password=readn(s,n)
            if version!=1 or user!=USER or password!=PASSWORD: s.sendall(b'\x01\x01'); return
            s.sendall(b'\x01\x00'); header=readn(s,4)
            if header!=b'\x05\x01\x00\x01': return
            readn(s,6); s.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01')
            while True:
                data=s.recv(4096)
                if not data: return
                s.sendall(data)
        except (OSError,EOFError): return

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True

def write_auth(path,user,password):
    path.write_bytes(bytes([len(user)])+user+bytes([len(password)])+password)
    path.chmod(0o600)

def start(port,path):
    env=os.environ.copy(); env['NAPTD_RELAY_TOKEN']=TOKEN
    if path: env['NAPTD_PROXY_AUTH_FILE']=str(path)
    return subprocess.Popen([str(ROOT/'socks_gateway'),'socks5',str(port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)

with Server(('127.0.0.1',0),Handler) as server, tempfile.TemporaryDirectory(dir='/private/tmp',prefix='socks-auth-test-') as directory:
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start(); path=Path(directory)/'auth'
    write_auth(path,USER,PASSWORD); good=start(server.server_address[1],path)
    try:
        ready,_,_=select.select([good.stdout],[],[],5)
        assert ready
        line=good.stdout.readline().strip(); assert line.startswith('gateway_ready:'),line
        tcp=int(line.split(':')[1])
        with socket.create_connection(('127.0.0.1',tcp),timeout=5) as s:
            s.settimeout(5); s.sendall(b'NAT1'+TOKEN.encode()+socket.inet_aton('203.0.113.2')+struct.pack('!H',443)+b'probe')
            assert readn(s,5)==b'probe'
    finally:
        good.terminate(); good.wait(timeout=5)
    write_auth(path,USER,b'wrong-password'); wrong=start(server.server_address[1],path)
    assert wrong.wait(timeout=7)==3
    missing=start(server.server_address[1],None); assert missing.wait(timeout=7)==3
    server.shutdown(); thread.join(timeout=2)
print('SOCKS5 auth: valid credentials accepted; invalid and missing credentials rejected')
