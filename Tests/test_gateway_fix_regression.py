#!/usr/bin/env python3
"""Black-box regression for revalidated second-audit fixes (loopback only).

Compiles an isolated copy: LAN interface discovery and the destination guard are
substituted exactly as the existing stability harness does. Uses disposable
directories under build/ and never touches production sessions or leases.
"""
import argparse
import contextlib
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
IP=socket.inet_aton('127.0.0.1')


def readn(sock,n):
    data=b''
    while len(data)<n:
        chunk=sock.recv(n-len(data))
        if not chunk: raise EOFError('closed')
        data+=chunk
    return data


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(60)
        try:
            while True:
                data=self.request.recv(65536)
                if not data: return
                self.request.sendall(data)
        except OSError: pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True


def build(work,sanitize=False,strict_guard=False):
    source=(ROOT/'Sources/socks_gateway.c').read_text()
    start=source.index('static int lan_wifi_address(')
    end=source.index('static int dns_skip_name(',start)
    source=source[:start]+'static int lan_wifi_address(struct in_addr *a) { a->s_addr=htonl(INADDR_LOOPBACK); return 1; }\n'+source[end:]
    if not strict_guard:
        guard='uint32_t host=ntohl(address);\n    return host && (host>>24)!=127;'
        assert source.count(guard)==1
        source=source.replace(guard,'return address==htonl(0x7f000001u);')
    path=work/('gateway-strict.c' if strict_guard else 'gateway.c'); path.write_text(source)
    binary=work/('gateway-strict' if strict_guard else 'gateway')
    subprocess.run(['/usr/bin/clang','-O1','-g','-Wall','-Wextra','-Werror','-pthread',
                    *(['-fsanitize=address,undefined'] if sanitize else []),
                    '-I'+str(ROOT/'Sources'),str(path),'-o',str(binary)],check=True,cwd=ROOT)
    return binary


@contextlib.contextmanager
def gateway(binary,work):
    auth=work/'auth'; auth.write_bytes(b'\x03Mac\x08testonly')
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1',0)); port=reserve.getsockname()[1]
    env={k:v for k,v in os.environ.items() if not k.startswith('NAPTD_')}
    env.update(NAPTD_RELAY_TOKEN='a'*32,NAPTD_LAN_INTERFACE='en0',NAPTD_LAN_PORT=str(port),
               NAPTD_LAN_AUTH_FILE=str(auth))
    proc=subprocess.Popen([str(binary),'direct','lo0'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
    try:
        assert select.select([proc.stdout],[],[],8)[0]
        line=proc.stdout.readline().strip(); assert line.startswith('gateway_ready:'),line
        yield port,int(line.split(':')[2]),proc
    finally:
        proc.terminate()
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
        error=proc.stderr.read()
        assert 'AddressSanitizer' not in error and 'runtime error:' not in error,error
        proc.stdout.close(); proc.stderr.close()


def login(port,timeout=4):
    sock=socket.create_connection(('127.0.0.1',port),timeout=3); sock.settimeout(timeout)
    sock.sendall(b'\x05\x01\x02'); assert readn(sock,2)==b'\x05\x02'
    sock.sendall(b'\x01\x03Mac\x08testonly'); assert readn(sock,2)==b'\x01\x00'
    return sock


def slow_handshake(port):
    holders=[]
    try:
        for _ in range(48):
            sock=socket.create_connection(('127.0.0.1',port),timeout=3)
            sock.settimeout(20)
            sock.sendall(b'\x05\x01\x02'); assert readn(sock,2)==b'\x05\x02'
            sock.sendall(b'\x01\x03Mac\x08testonly'); assert readn(sock,2)==b'\x01\x00'
            # Stop here: the server waits for the request, so the slot is held.
            holders.append(sock)
        start=time.monotonic()
        released=[]
        for sock in holders:
            if select.select([sock],[],[],19)[0]:
                try: released.append(sock.recv(64))
                except OSError: released.append(b'')
            sock.close()
        elapsed=time.monotonic()-start
        assert len(released)==48,f'only {len(released)}/48 stalled slots closed'
        # Individual recv timeouts allowed 15s+; an absolute deadline must close
        # every stalled slot near once, not once per read.
        assert elapsed<12,f'stalled slots took {elapsed:.1f}s to close'
        deadline=time.monotonic()+5
        while True:
            try:
                fresh=login(port); fresh.close(); break
            except (AssertionError,EOFError,OSError):
                assert time.monotonic()<deadline,'handshake slots never recovered'
                time.sleep(.05)
        return {'stalled_slots':48,'released':len(released),'seconds':round(elapsed,2),'recovered':True}
    finally:
        for sock in holders:
            try: sock.close()
            except OSError: pass


def udp1_policy(port,internal):
    token=b'a'*32
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as receiver:
        receiver.bind(('127.0.0.1',0)); receiver.settimeout(.8)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
            sender.sendto(b'UDP1'+token+socket.inet_aton('127.0.0.1')+
                          struct.pack('!H',receiver.getsockname()[1])+b'probe',('127.0.0.1',internal))
        assert not select.select([receiver],[],[],.8)[0],'UDP1 relay forwarded a loopback destination'
    return {'loopback_destination_rejected':True}


def udp_truncation_and_data(port):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as target, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        target.bind(('127.0.0.1',0)); target.settimeout(3)
        client.bind(('127.0.0.1',0)); client.settimeout(3)
        control=login(port)
        control.sendall(b'\x05\x03\x00\x01'+b'\0'*4+b'\0\0')
        reply=readn(control,10); assert reply[:2]==b'\x05\x00'
        relay=('127.0.0.1',struct.unpack('!H',reply[8:])[0])
        frame=b'\0\0\0\1'+IP+struct.pack('!H',target.getsockname()[1])
        for size in (9000,500):
            client.sendto(frame+bytes([size&255])*size,relay)
            payload,peer=target.recvfrom(70000); assert payload==bytes([size&255])*size
            target.sendto(payload,peer)
            assert client.recv(70000)==frame+payload
        control.close()
        return {'payloads':[9000,500],'exact':True}


def tcp_idle_short(port):
    # The 30s poll wake-up must not itself close an idle connection.
    with Server(('127.0.0.1',0),Echo) as server:
        threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            sock=login(port)
            sock.sendall(b'\x05\x01\x00\x01'+IP+struct.pack('!H',server.server_address[1]))
            assert readn(sock,10)[:2]==b'\x05\x00'
            sock.sendall(b'before'); assert readn(sock,6)==b'before'
            assert not select.select([sock],[],[],35)[0],'idle TCP relay closed at the poll tick'
            sock.sendall(b'after'); assert readn(sock,5)==b'after'
            sock.close()
            return {'idle_seconds':35,'still_open':True}
        finally: server.shutdown()


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--sanitize',action='store_true')
    args=parser.parse_args()
    work=Path(tempfile.mkdtemp(prefix='gateway-fix-',dir=ROOT/'build'))
    binary=build(work,args.sanitize)
    strict=build(work,args.sanitize,strict_guard=True)
    results={}
    with gateway(binary,work) as (port,internal,proc):
        for name,case in (('tcp_idle_short',tcp_idle_short),
                          ('udp_data',udp_truncation_and_data),('slow_handshake',slow_handshake)):
            try:
                results[name]={'pass':True,**case(port)}
            except BaseException as error: results[name]={'pass':False,'error':repr(error)}
            print(name+': '+json.dumps(results[name]),flush=True)
    # The destination policy must be tested without the loopback-only test guard.
    with gateway(strict,work) as (port,internal,proc):
        try: results['udp1_policy']={'pass':True,**udp1_policy(port,internal)}
        except BaseException as error: results['udp1_policy']={'pass':False,'error':repr(error)}
        print('udp1_policy: '+json.dumps(results['udp1_policy']),flush=True)
    report=work/'results.json'; report.write_text(json.dumps(results,indent=2))
    print('Report:',report)
    return 0 if all(v['pass'] for v in results.values()) else 1


if __name__=='__main__': raise SystemExit(main())
