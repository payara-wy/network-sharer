#!/usr/bin/env python3
"""Test the actual sandboxed TCP/DNS interposition through a local SOCKS server."""
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading

ROOT=Path(__file__).resolve().parents[1]
def readn(sock,n):
    result=b''
    while len(result)<n:
        data=sock.recv(n-len(result))
        if not data: raise EOFError()
        result+=data
    return result

class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        sock=self.request; sock.settimeout(8)
        try:
            assert readn(sock,3)==b'\x05\x01\x00'
            sock.sendall(b'\x05\x00'); request=readn(sock,10)
            port=struct.unpack('!H',request[8:])[0]
            sock.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01')
            if port==53:
                size=struct.unpack('!H',readn(sock,2))[0]; query=readn(sock,size)
                answer=query[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+query[12:]+b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'+socket.inet_aton('203.0.113.9')
                sock.sendall(struct.pack('!H',len(answer))+answer)
            elif port==80:
                sock.recv(4096); sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
        except (EOFError,OSError,AssertionError): pass

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True

with tempfile.TemporaryDirectory(prefix='networksharer-shim-test-',dir='/private/tmp') as tmp:
    probe=Path(tmp)/'shim-probe'
    subprocess.run(['/usr/bin/clang','-O2',str(ROOT/'Tests/shim_proxy_probe.c'),'-o',str(probe)],check=True)
    with Server(('127.0.0.1',0),Proxy) as server:
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        env=dict(os.environ,NETWORKSHARER_TEST_SHIM_PROBE=str(probe))
        subprocess.run(['/usr/bin/python3',str(ROOT/'Tests/test_shim_proxy.py'),str(server.server_address[1])],
                       env=env,check=True,timeout=40)
        server.shutdown(); thread.join(timeout=3)
