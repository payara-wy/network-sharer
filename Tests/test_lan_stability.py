#!/usr/bin/env python3
"""Reproducible LAN stability cases, only loopback endpoints.

Compile an isolated copy: keep real sockets/IP_BOUND_IF via lo0, substitute LAN
interface discovery and allow only the test's loopback destination. A synthetic
slow.test resolver supplies a deterministic 2-second DNS delay. No real DNS,
route changes, admin privileges or production sessions are used.
"""
import argparse
import contextlib
import hashlib
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

ROOT = Path(__file__).resolve().parents[1]
IP = socket.inet_aton('127.0.0.1')


def readn(s, n):
    b = b''
    while len(b) < n:
        part = s.recv(n - len(b))
        if not part:
            raise EOFError('connection closed')
        b += part
    return b


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(180)
        try:
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                self.request.sendall(data)
        except OSError:
            pass


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def build(source_root, work, sanitize=False):
    source = (source_root / 'Sources/socks_gateway.c').read_text()
    start = source.index('static int lan_wifi_address(')
    end = source.index('static int dns_skip_name(', start)
    source = source[:start] + 'static int lan_wifi_address(struct in_addr *a) { a->s_addr=htonl(INADDR_LOOPBACK); return 1; }\n' + source[end:]
    guard = 'return host && (host>>24)!=127;'
    assert source.count(guard) == 1
    source = source.replace(guard, 'return host == INADDR_LOOPBACK;')
    marker = '/* Send a SOCKS5 CONNECT with a domain name'
    if 'static int resolve_ipv4_name_ttl(' in source:
        source = source.replace('static int resolve_ipv4_name_ttl(', 'static int real_resolve_ipv4_name_ttl(', 1)
        source = source.replace('return resolve_ipv4_name_ttl(name,out,NULL);', 'return real_resolve_ipv4_name_ttl(name,out,NULL);')
        stub = '''static int resolve_ipv4_name_ttl(const char *name,struct in_addr *out,uint32_t *ttl) {
    if (!strcmp(name,"slow.test")) {
        struct timespec delay={.tv_sec=2}; nanosleep(&delay,NULL);
        out->s_addr=htonl(INADDR_LOOPBACK); if(ttl)*ttl=60; return 1;
    }
    return real_resolve_ipv4_name_ttl(name,out,ttl);
}
'''
    else:
        source = source.replace('static int resolve_ipv4_name(', 'static int real_resolve_ipv4_name(', 1)
        stub = '''static int resolve_ipv4_name(const char *name,struct in_addr *out) {
    if (!strcmp(name,"slow.test")) {
        struct timespec delay={.tv_sec=2}; nanosleep(&delay,NULL);
        out->s_addr=htonl(INADDR_LOOPBACK); return 1;
    }
    return real_resolve_ipv4_name(name,out);
}
'''
    assert source.count(marker) == 1
    source = source.replace(marker, stub + marker)
    path = work / 'gateway.c'; path.write_text(source)
    binary = work / 'gateway'
    subprocess.run(['/usr/bin/clang', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
                    *(['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if sanitize else []),
                    '-I' + str(source_root / 'Sources'), str(path), '-o', str(binary)], check=True, cwd=ROOT)
    return binary


@contextlib.contextmanager
def gateway(binary, work):
    auth = work / 'auth'; auth.write_bytes(b'\x03Mac\x08testonly')
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith('NAPTD_')}
    env.update(NAPTD_CONTROLLER_PID=str(os.getpid()), NAPTD_LAN_INTERFACE='en0',
               NAPTD_LAN_PORT=str(port), NAPTD_LAN_AUTH_FILE=str(auth), NAPTD_RELAY_TOKEN='a'*32)
    proc = subprocess.Popen([str(binary), 'direct', 'lo0'], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=env)
    try:
        assert select.select([proc.stdout], [], [], 8)[0], 'startup timeout'
        line = proc.stdout.readline().strip()
        assert line.startswith('gateway_ready:'), line
        yield port, proc
    finally:
        proc.terminate()
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
        error = proc.stderr.read()
        assert 'AddressSanitizer' not in error and 'runtime error:' not in error, error
        proc.stdout.close(); proc.stderr.close()


def login(port):
    s = socket.create_connection(('127.0.0.1', port), timeout=3)
    s.settimeout(4)
    try:
        s.sendall(b'\x05\x01\x02'); assert readn(s, 2) == b'\x05\x02'
        s.sendall(b'\x01\x03Mac\x08testonly'); assert readn(s, 2) == b'\x01\x00'
        return s
    except BaseException:
        s.close(); raise


def associate(port, declared=0):
    c = login(port)
    c.sendall(b'\x05\x03\x00\x01' + b'\0'*4 + struct.pack('!H', declared))
    reply = readn(c, 10)
    if reply[:2] != b'\x05\x00': c.close(); raise AssertionError(reply)
    return c, ('127.0.0.1', int.from_bytes(reply[8:], 'big'))


def client_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 0)); s.settimeout(4)
    return s


def frame(port, body, domain=False):
    return (b'\0\0\0\3\x09slow.test' if domain else b'\0\0\0\1'+IP) + struct.pack('!H', port) + body


def roundtrip(udp, relay, target, body):
    udp.sendto(frame(target.getsockname()[1], body), relay)
    payload, peer = target.recvfrom(65535)
    assert payload == body
    target.sendto(payload, peer)
    assert udp.recv(65535) == frame(target.getsockname()[1], body)
    return peer


def idle_case(port, seconds):
    control, relay = associate(port)
    try:
        with client_udp() as udp, client_udp() as target:
            roundtrip(udp, relay, target, b'before-idle')
            closed = select.select([control], [], [], seconds)[0]
            assert not closed, 'UDP association closed during %ss idle while control stayed open' % seconds
            roundtrip(udp, relay, target, b'after-idle')
        return {'idle_seconds': seconds, 'resumed': True}
    finally: control.close()


def capacity_case(port):
    with TCPServer(('127.0.0.1', 0), Echo) as server, contextlib.ExitStack() as stack:
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            for _ in range(48):
                s = stack.enter_context(login(port))
                s.sendall(b'\x05\x01\x00\x01'+IP+struct.pack('!H', server.server_address[1]))
                assert readn(s, 10)[:2] == b'\x05\x00'
            c, relay = associate(port); stack.enter_context(c)
            with client_udp() as udp, client_udp() as target: roundtrip(udp, relay, target, b'udp-with-48-tcp')
            # A new TCP connection must also work, not just a UDP special case.
            s = stack.enter_context(login(port))
            s.sendall(b'\x05\x01\x00\x01'+IP+struct.pack('!H', server.server_address[1]))
            assert readn(s, 10)[:2] == b'\x05\x00'
            s.sendall(b'new-tcp'); assert readn(s, 7) == b'new-tcp'
            return {'held_tcp': 48, 'additional_udp_and_tcp': True}
        finally: server.shutdown()


def budget_case(port):
    controls = []
    try:
        for _ in range(32):
            control, _ = associate(port); controls.append(control)
        # The UDP limit must stay enforced without exhausting handshake slots.
        with login(port) as extra:
            extra.sendall(b'\x05\x03\x00\x01'+b'\0'*6)
            assert readn(extra,10)[1] != 0, 'UDP association cap not enforced'
        controls.pop().close()
        deadline=time.monotonic()+3
        while True:
            try:
                control, _ = associate(port); controls.append(control); break
            except (AssertionError, EOFError, OSError):
                assert time.monotonic()<deadline, 'closed UDP slot was not released'
                threading.Event().wait(.02)
        return {'udp_limit':32, 'overflow_rejected':True, 'closed_slot_reusable':True}
    finally:
        for control in controls: control.close()


def slow_dns_case(port):
    control, relay = associate(port)
    try:
        with client_udp() as udp, client_udp() as target:
            roundtrip(udp, relay, target, b'known-flow')
            udp.sendto(frame(target.getsockname()[1], b'pending-domain', True), relay)
            start = time.monotonic()
            udp.sendto(frame(target.getsockname()[1], b'fast-ip'), relay)
            target.settimeout(.8)
            payload, peer = target.recvfrom(65535)
            assert payload == b'fast-ip', 'DNS resolution stalled the already-known IPv4 flow'
            target.sendto(payload, peer)
            assert udp.recv(65535)[10:] == b'fast-ip'
            elapsed = time.monotonic() - start
            target.settimeout(4)
            payload, peer = target.recvfrom(65535); assert payload == b'pending-domain'
            target.sendto(payload, peer); assert udp.recv(65535)[10:] == payload
            return {'existing_flow_delay_ms': round(elapsed * 1000)}
    finally: control.close()


def domain_burst_case(port):
    c, relay = associate(port)
    try:
        with client_udp() as udp, client_udp() as target:
            # All ten packets use the same hostname. One DNS lookup should
            # release the burst, not ten sequential two-second lookups.
            for n in range(10): udp.sendto(frame(target.getsockname()[1], bytes([n]), True), relay)
            end = time.monotonic()+3.5
            received = []
            while len(received)<10:
                target.settimeout(max(.01, end-time.monotonic()))
                body, peer = target.recvfrom(65535); received.append(body)
                target.sendto(body, peer)
                assert udp.recv(65535)[10:] == body
            assert received == [bytes([n]) for n in range(10)]
            assert time.monotonic() <= end, 'domain burst exceeded its total deadline'
            return {'domain_packets_delivered': len(received)}
    finally: c.close()


def churn_case(port):
    c, relay = associate(port)
    try:
        with contextlib.ExitStack() as stack:
            udp = stack.enter_context(client_udp())
            first = stack.enter_context(client_udp())
            original = roundtrip(udp, relay, first, b'first')
            # Distinct timestamp avoids ties accidentally retaining the first
            # flow when the table evicts another equally-recent entry.
            threading.Event().wait(1.1)
            for n in range(40):
                target = stack.enter_context(client_udp())
                roundtrip(udp, relay, target, str(n).encode())
            returned = roundtrip(udp, relay, first, b'first-again')
            assert original == returned, '41 live destinations recycled the active source port'
            for n in range(87):
                target = stack.enter_context(client_udp())
                roundtrip(udp, relay, target, bytes([n]))
            extra = stack.enter_context(client_udp())
            udp.sendto(frame(extra.getsockname()[1], b'overflow'), relay)
            extra.settimeout(.2)
            try:
                extra.recvfrom(65535)
                raise AssertionError('destination cap was not enforced')
            except socket.timeout:
                pass
            assert roundtrip(udp, relay, first, b'preserved-at-cap') == original
            return {'live_destinations': 128, 'overflow_rejected': True, 'first_source_port_preserved': True}
    finally: c.close()


def invalid_first_case(port):
    c, relay = associate(port)
    try:
        with client_udp() as bad, client_udp() as good, client_udp() as target:
            # Correct IP but unsupported ATYP: must not seize the association.
            bad.sendto(b'\0\0\0\xff'+b'\0'*8, relay)
            roundtrip(good, relay, target, b'valid-after-invalid')
            return {'invalid_first_packet_ignored': True}
    finally: c.close()


def tcp_case(port):
    with TCPServer(('127.0.0.1', 0), Echo) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with login(port) as s:
                s.sendall(b'\x05\x01\x00\x01'+IP+struct.pack('!H', server.server_address[1]))
                assert readn(s, 10)[:2] == b'\x05\x00'
                payload = bytes(range(256))*16384
                errors = []
                def send():
                    try: s.sendall(payload); s.shutdown(socket.SHUT_WR)
                    except Exception as error: errors.append(str(error))
                sender = threading.Thread(target=send); sender.start()
                received = bytearray()
                while True:
                    data = s.recv(65536)
                    if not data: break
                    received.extend(data)
                sender.join(5)
                assert not sender.is_alive() and not errors, errors
                assert received == payload, (len(received), len(payload))
                return {'bidirectional_bytes': len(received), 'half_close': True}
        finally: server.shutdown()


def soak_case(port, seconds):
    controls = []
    try:
        with contextlib.ExitStack() as stack:
            peers = []
            for _ in range(4):
                c, relay = associate(port); controls.append(c)
                peers.append((stack.enter_context(client_udp()), relay, stack.enter_context(client_udp())))
            deadline = time.monotonic()+seconds
            packets = 0
            while time.monotonic()<deadline:
                for udp, relay, target in peers:
                    roundtrip(udp, relay, target, struct.pack('!I', packets)+b'x'*1200)
                    packets += 1
                threading.Event().wait(.02)
            for c in controls:
                assert not select.select([c], [], [], 0)[0], 'active association closed'
            return {'seconds': seconds, 'clients': 4, 'roundtrips': packets, 'lost': 0}
    finally:
        for c in controls: c.close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--case', choices=['quick', 'idle', 'soak', 'all'], default='quick')
    parser.add_argument('--idle-seconds', type=int, default=125)
    parser.add_argument('--sanitize', action='store_true')
    args=parser.parse_args()
    work=Path(tempfile.mkdtemp(prefix='lan-stability-',dir=ROOT/'build'))
    os.environ['TMPDIR']=str(work)
    binary=build(args.source_root,work,args.sanitize)
    cases={} if args.case in ('idle', 'soak') else {'capacity':capacity_case,'budgets':budget_case,'slow_dns':slow_dns_case,'domain_burst':domain_burst_case,'churn':churn_case,'invalid_first':invalid_first_case,'tcp_bulk':tcp_case}
    if args.case in ('idle', 'all'): cases['idle']=lambda port:idle_case(port,args.idle_seconds)
    if args.case in ('soak', 'all'): cases['soak']=lambda port:soak_case(port,args.idle_seconds)
    results={}
    for name,case in cases.items():
        try:
            with gateway(binary,work) as (port,proc): results[name]={'pass':True, **case(port)}
        except Exception as error: results[name]={'pass':False,'error':repr(error)}
        print(name+': '+json.dumps(results[name]),flush=True)
    report={'source':str(args.source_root),'sanitized':args.sanitize,'results':results}
    (work/'results.json').write_text(json.dumps(report,indent=2))
    print('Report:',work/'results.json',flush=True)
    return 0 if all(r['pass'] for r in results.values()) else 1


if __name__=='__main__': raise SystemExit(main())
