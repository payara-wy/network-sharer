#!/usr/bin/env python3
"""Idle TCP relay check against the fixed gateway built from current source."""
import argparse
import importlib.util
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


def build(work):
    source=(ROOT/'Sources/socks_gateway.c').read_text()
    start=source.index('static int lan_wifi_address(')
    end=source.index('static int dns_skip_name(',start)
    source=source[:start]+'static int lan_wifi_address(struct in_addr *a) { a->s_addr=htonl(INADDR_LOOPBACK); return 1; }\n'+source[end:]
    guard='uint32_t host=ntohl(address);\n    return host && (host>>24)!=127;'
    source=source.replace(guard,'return address==htonl(0x7f000001u);')
    path=work/'gateway.c'; path.write_text(source)
    binary=work/'gateway'
    subprocess.run(['/usr/bin/clang','-O1','-g','-Wall','-Wextra','-Werror','-pthread',
                    '-I'+str(ROOT/'Sources'),str(path),'-o',str(binary)],check=True)
    return binary


class IdleEcho(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(600)
        try:
            while True:
                data=self.request.recv(65536)
                if not data: return
                self.request.sendall(data)
        except OSError: return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True


def login(port):
    sock=socket.create_connection(('127.0.0.1',port),timeout=3); sock.settimeout(15)
    sock.sendall(b'\x05\x01\x02'); assert sock.recv(2)==b'\x05\x02'
    sock.sendall(b'\x01\x03Mac\x08testonly'); assert sock.recv(2)==b'\x01\x00'
    return sock


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--seconds',type=int,default=315)
    args=parser.parse_args()
    work=Path(tempfile.mkdtemp(prefix='idle-fixed-',dir=ROOT/'build'))
    binary=build(work)
    auth=work/'auth'; auth.write_bytes(b'\x03Mac\x08testonly')
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1',0)); port=reserve.getsockname()[1]
    env={k:v for k,v in os.environ.items() if not k.startswith('NAPTD_')}
    env.update(NAPTD_RELAY_TOKEN='a'*32,NAPTD_LAN_INTERFACE='en0',NAPTD_LAN_PORT=str(port),NAPTD_LAN_AUTH_FILE=str(auth))
    gateway=subprocess.Popen([str(binary),'direct','lo0'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        assert select.select([gateway.stdout],[],[],8)[0]
        line=gateway.stdout.readline().strip(); assert line.startswith('gateway_ready:'),line
        with Server(('127.0.0.1',0),IdleEcho) as server:
            threading.Thread(target=server.serve_forever,daemon=True).start()
            sock=login(port)
            sock.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',server.server_address[1]))
            assert sock.recv(10)[:2]==b'\x05\x00'
            sock.sendall(b'before-idle'); assert sock.recv(11)==b'before-idle'
            report={'seconds_waited':args.seconds,'closed_during_idle':False}
            start=time.monotonic()
            while time.monotonic()-start<args.seconds:
                if select.select([sock],[],[],min(2,args.seconds-(time.monotonic()-start)))[0]:
                    report['closed_during_idle']=True
                    report['elapsed_seconds']=round(time.monotonic()-start,2)
                    break
            if not report['closed_during_idle']:
                sock.sendall(b'after-idle'); assert sock.recv(10)==b'after-idle'
                report['resumed']=True
            sock.close(); server.shutdown()
        report['note']='idle TCP stays open; kernel keepalive owns dead peers'
        print(json.dumps(report),flush=True)
        (work/'result.json').write_text(json.dumps(report,indent=2))
    finally:
        gateway.terminate()
        try: gateway.wait(timeout=5)
        except subprocess.TimeoutExpired: gateway.kill(); gateway.wait()
        error=gateway.stderr.read(); assert 'AddressSanitizer' not in error,error
        gateway.stdout.close(); gateway.stderr.close()


if __name__=='__main__': main()
