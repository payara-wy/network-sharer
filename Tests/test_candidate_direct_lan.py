#!/usr/bin/env python3
"""Exercise the actual signed gateway under the unchanged direct-mode sandbox.
Only this Mac's Wi-Fi address is contacted; no interface or route changes.
"""
import argparse
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]

def readn(s,n):
    result=b''
    while len(result)<n:
        data=s.recv(n-len(result))
        if not data: raise EOFError('closed')
        result+=data
    return result

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            while True:
                data=self.request.recv(65536)
                if not data: break
                self.request.sendall(data)
        except OSError: pass

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('app',type=Path)
    parser.add_argument('--idle-seconds', type=int, default=0)
    args=parser.parse_args()
    app=args.app.resolve(strict=True); assert app.is_relative_to(ROOT/'build')
    work=Path(tempfile.mkdtemp(prefix='candidate-direct-',dir=ROOT/'build'))
    address=subprocess.check_output(['/usr/sbin/ipconfig','getifaddr','en0'],text=True).strip()
    auth=work/'auth'; auth.write_bytes(b'\x03Mac\x08testonly')
    with socket.socket() as reserved:
        reserved.bind((address,0)); port=reserved.getsockname()[1]
    # Same profile as engine.sh direct mode. User files are denied, with this
    # disposable test credential file as the sole explicit read exception.
    profile='(version 1) (allow default) (deny file-write*) (deny network*) '
    profile+='(deny file-read* (subpath "/Users")) (deny file-read* (subpath "/private/var/root")) (deny file-read* (subpath "/Volumes")) '
    profile+='(allow network-bind) (allow network-inbound) (allow network-outbound) '
    profile+='(allow file-read* (literal '+json.dumps(str(auth))+'))'
    env={k:v for k,v in os.environ.items() if not k.startswith('NAPTD_')}
    env.update(TMPDIR=str(work),NAPTD_CONTROLLER_PID=str(os.getpid()),NAPTD_LAN_INTERFACE='en0',
               NAPTD_LAN_PORT=str(port),NAPTD_LAN_AUTH_FILE=str(auth),NAPTD_RELAY_TOKEN='a'*32)
    gateway=app/'Contents/MacOS/socks_gateway'
    p=subprocess.Popen(['/usr/bin/sandbox-exec','-p',profile,str(gateway),'direct','en0'],env=env,
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    controls=[]
    def login():
        s=socket.create_connection((address,port),timeout=5); controls.append(s); s.settimeout(5)
        s.sendall(b'\x05\x01\x02'); assert readn(s,2)==b'\x05\x02'
        s.sendall(b'\x01\x03Mac\x08testonly'); assert readn(s,2)==b'\x01\x00'
        return s
    result={}
    try:
        assert select.select([p.stdout],[],[],8)[0]
        assert p.stdout.readline().startswith('gateway_ready:')
        with Server((address,0),Echo) as server:
            threading.Thread(target=server.serve_forever,daemon=True).start()
            try:
                s=login(); s.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(address)+struct.pack('!H',server.server_address[1]))
                assert readn(s,10)[:2]==b'\x05\x00'
                for n in range(128):
                    body=struct.pack('!I',n)+b'x'*4096
                    s.sendall(body); assert readn(s,len(body))==body
                s.close(); result['tcp_echoes']=128
            finally: server.shutdown()
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as echo:
            udp.bind((address,0)); echo.bind((address,0)); udp.settimeout(3); echo.settimeout(3)
            c=login()
            c.sendall(b'\x05\x03\x00\x01'+b'\0'*6)
            reply=readn(c,10); assert reply[:2]==b'\x05\x00'
            relay=(socket.inet_ntoa(reply[4:8]),int.from_bytes(reply[8:],'big'))
            header=b'\0\0\0\1'+socket.inet_aton(address)+struct.pack('!H',echo.getsockname()[1])
            for n in range(1000):
                body=struct.pack('!I',n)+b'y'*1200
                udp.sendto(header+body,relay)
                data,peer=echo.recvfrom(4096); assert data==body
                echo.sendto(data,peer); assert udp.recv(4096)==header+body
            result['udp_echoes']=1000
            if args.idle_seconds:
                assert not select.select([c],[],[],args.idle_seconds)[0], 'association closed while idle'
                body=b'after-real-idle'
                udp.sendto(header+body,relay)
                data,peer=echo.recvfrom(4096); assert data==body
                echo.sendto(data,peer); assert udp.recv(4096)==header+body
                result['idle_resume_seconds']=args.idle_seconds
        result.update(sandbox='direct unchanged',test_scope='local Wi-Fi address only',pass_all=True)
        print(json.dumps(result),flush=True)
    finally:
        for s in controls: s.close()
        p.terminate()
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)
        stderr=p.stderr.read(); p.stdout.close(); p.stderr.close()
        (work/'stderr.log').write_text(stderr)
        (work/'result.json').write_text(json.dumps(result,indent=2))

if __name__=='__main__': main()
