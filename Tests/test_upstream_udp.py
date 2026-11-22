#!/usr/bin/env python3
"""Deterministic SOCKS5 UDP tests. All network endpoints are loopback mocks."""
import contextlib
import importlib.util
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

ROOT = Path(__file__).resolve().parents[1]
TOKEN = 'a' * 32
USER, KEY = b'client', b'test-only'
TARGET = socket.inet_aton('203.0.113.12')
HEADER = b'\0\0\0\1' + TARGET + struct.pack('!H', 12345)


def readn(s, n):
    data = b''
    while len(data) < n:
        part = s.recv(n-len(data))
        if not part: raise EOFError()
        data += part
    return data


class MockHandler(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request; s.settimeout(4)
        try:
            version, count = readn(s, 2); methods = readn(s, count)
            wanted = 2 if self.server.auth else 0
            if version != 5 or wanted not in methods: return
            s.sendall(bytes([5, wanted]))
            if wanted == 2:
                version, n = readn(s, 2); user = readn(s, n)
                key = readn(s, readn(s, 1)[0])
                ok = version == 1 and user == USER and key == KEY
                s.sendall(bytes([1, 0 if ok else 1]))
                if not ok: return
            command = readn(s, 10)
            if command[:4] != b'\x05\x03\x00\x01': return
            endpoint = (socket.inet_ntoa(command[4:8]), struct.unpack('!H', command[8:])[0])
            assert endpoint[0] == '127.0.0.1' and endpoint[1], endpoint
            if self.server.reject:
                s.sendall(b'\x05\x07\x00\x01' + b'\0'*6); return
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.bind(('127.0.0.1', 0))
                s.sendall(b'\x05\x00\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H', udp.getsockname()[1]))
                self.server.opened += 1
                self.server.controls.append(s)
                try:
                    while not self.server.stop.is_set():
                        ready, _, _ = select.select([s, udp], [], [], .1)
                        if s in ready: return
                        if udp in ready:
                            data, source = udp.recvfrom(65535)
                            assert source == endpoint
                            self.server.packets.append(data)
                            if data[10:] == b'badframes':
                                # Invalid replies must not leak to clients.
                                udp.sendto(data[:2]+b'\x01'+data[3:], source)
                                udp.sendto(b'\x01'+data[1:], source)
                                udp.sendto(data[:9], source)
                                udp.sendto(data[:8]+struct.pack('!H', 9999)+data[10:], source)
                            elif data[10:] == b'close-control':
                                return
                            else:
                                udp.sendto(data, source)
                finally:
                    self.server.controls.remove(s)
                    self.server.closed += 1
        except (EOFError, OSError):
            pass


class MockProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    def __init__(self, auth=False, reject=False):
        self.auth, self.reject = auth, reject
        self.stop = threading.Event(); self.packets = []; self.controls = []
        self.opened = self.closed = 0
        super().__init__(('127.0.0.1', 0), MockHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()
    def finish(self):
        self.stop.set(); self.shutdown(); self.server_close()


def until(test, timeout=5):
    end = time.monotonic()+timeout
    while time.monotonic()<end:
        if test(): return
        time.sleep(.02)
    raise AssertionError('condition timed out')


@contextlib.contextmanager
def gateway(binary, proxy, work, lan=True, lan_udp_disabled=False):
    env = {k:v for k,v in os.environ.items() if not k.startswith('NAPTD_')}
    env.update(NAPTD_RELAY_TOKEN=TOKEN, NAPTD_DNS_SERVER='203.0.113.53')
    auth = work/'auth'; auth.write_bytes(bytes([len(USER)])+USER+bytes([len(KEY)])+KEY)
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]
    if lan: env.update(NAPTD_LAN_PORT=str(port), NAPTD_LAN_INTERFACE='en0', NAPTD_LAN_AUTH_FILE=str(auth))
    if lan_udp_disabled: env['NAPTD_LAN_UDP_DISABLED'] = '1'
    if proxy.auth: env['NAPTD_PROXY_AUTH_FILE'] = str(auth)
    p = subprocess.Popen([str(binary), 'socks5', str(proxy.server_address[1])], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([p.stdout], [], [], 6)[0]
        line = p.stdout.readline().strip(); assert line.startswith('gateway_ready:'), line
        yield port, int(line.split(':')[2])
    finally:
        p.terminate(); p.wait(timeout=5)
        stderr=p.stderr.read()
        assert 'AddressSanitizer' not in stderr and 'runtime error:' not in stderr, stderr


def lan_associate(port, udp):
    s = socket.create_connection(('127.0.0.1', port), timeout=5); s.settimeout(5)
    s.sendall(b'\x05\x01\x02'); assert readn(s, 2) == b'\x05\x02'
    s.sendall(bytes([1, len(USER)])+USER+bytes([len(KEY)])+KEY); assert readn(s, 2) == b'\x01\x00'
    s.sendall(b'\x05\x03\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H', udp.getsockname()[1]))
    reply = readn(s, 10)
    return s, reply


def udp_client():
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', 0)); s.settimeout(2)
    return s


def main():
    work=Path(tempfile.mkdtemp(prefix='udp-tests-', dir=ROOT/'build'))
    source=(ROOT/'Sources/socks_gateway.c').read_text()
    a=source.index('static int lan_wifi_address('); b=source.index('static int dns_skip_name(', a)
    # Only interface discovery is substituted; proxy protocol/guards are real.
    source=source[:a]+'static int lan_wifi_address(struct in_addr *out) { out->s_addr=htonl(INADDR_LOOPBACK); return 1; }\n'+source[b:]
    src=work/'gateway.c'; src.write_text(source); binary=work/'gateway'
    subprocess.run(['/usr/bin/clang','-O1','-g','-fsanitize=address,undefined','-Wall','-Wextra','-Werror',
                    '-pthread','-I'+str(ROOT/'Sources'),str(src),'-o',str(binary)],check=True)
    for auth in (False, True):
        proxy=MockProxy(auth=auth)
        try:
            with gateway(binary, proxy, work) as (port, internal):
                with udp_client() as one, udp_client() as two:
                    c1,r1=lan_associate(port,one); c2,r2=lan_associate(port,two)
                    try:
                        assert r1[:2]==r2[:2]==b'\x05\x00'
                        a1=('127.0.0.1',struct.unpack('!H',r1[8:])[0]); a2=('127.0.0.1',struct.unpack('!H',r2[8:])[0])
                        assert a1!=a2, 'same-IP clients must get independent associations'
                        for sock,relay,text in ((one,a1,b'one'),(two,a2,b'two'),(one,a1,b'')):
                            sock.sendto(HEADER+text,relay); assert sock.recv(65535)==HEADER+text
                        # Invalid downstream packet must never reach upstream.
                        count=len(proxy.packets)
                        one.sendto(b'\0\0\1\1'+HEADER[4:]+b'fragment',a1)
                        one.settimeout(.25)
                        try: one.recv(65535); raise AssertionError('fragment returned')
                        except socket.timeout: pass
                        assert len(proxy.packets)==count
                        one.sendto(HEADER+b'badframes',a1)
                        try: one.recv(65535); raise AssertionError('invalid upstream reply returned')
                        except socket.timeout: pass
                        # Wrong client port cannot use another authenticated association.
                        two.sendto(HEADER+b'wrong-port',a1)
                        one.sendto(HEADER+b'ready',a1); one.settimeout(2)
                        assert one.recv(65535)==HEADER+b'ready'
                        assert not any(p.endswith(b'wrong-port') for p in proxy.packets)
                        closed=proxy.closed; c1.close(); until(lambda:proxy.closed>closed)
                        two.sendto(HEADER+b'still-open',a2); assert two.recv(65535)==HEADER+b'still-open'
                        two.sendto(HEADER+b'close-control',a2)
                        assert c2.recv(1)==b'', 'upstream control closure must close downstream association'
                    finally: c1.close(); c2.close()
                # Token UDP1 path for physical clients, including zero payload.
                with udp_client() as local:
                    header=b'UDP1'+TOKEN.encode()+TARGET+struct.pack('!H',12345)
                    for text in (b'token-path',b''):
                        local.sendto(header+text,('127.0.0.1',internal)); assert local.recv(65535)==header+text
                    local.sendto(header+b'close-control',('127.0.0.1',internal))
                    until(lambda: proxy.closed>=proxy.opened)
                    local.sendto(header+b'reconnected',('127.0.0.1',internal)); assert local.recv(65535)==header+b'reconnected'
            until(lambda: proxy.closed==proxy.opened)
        finally: proxy.finish()
    # Strict upstream mode: LAN UDP is rejected explicitly, token UDP still works.
    strict=MockProxy()
    try:
        with gateway(binary, strict, work, lan_udp_disabled=True) as (port, internal), udp_client() as udp:
            control, reply = lan_associate(port, udp)
            assert reply[1] == 7, reply
            control.close()
            header=b'UDP1'+TOKEN.encode()+TARGET+struct.pack('!H',12345)
            udp.sendto(header+b'usb-path',('127.0.0.1',internal))
            assert udp.recv(65535)==header+b'usb-path'
    finally:
        strict.finish()

    # Upstream rejection must return error, never open a direct flow.
    reject=MockProxy(reject=True)
    try:
        with gateway(binary,reject,work) as (port,internal), udp_client() as udp:
            control,reply=lan_associate(port,udp)
            assert reply[1]==7; control.close()
            udp.sendto(b'UDP1'+TOKEN.encode()+TARGET+struct.pack('!H',12345)+b'blocked',('127.0.0.1',internal))
            udp.settimeout(.3)
            try: udp.recv(65535); raise AssertionError('unsupported upstream leaked data')
            except socket.timeout: pass
            assert not reject.packets
    finally: reject.finish()
    print('PASS: UDP LAN/token paths, auth, same-IP isolation, zero payload, bad frames, close/reconnect, no fallback, sanitizers')
    print('Work:', work)


if __name__=='__main__': main()
