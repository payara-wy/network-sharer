#!/usr/bin/env python3
"""Verify configurable DNS is used for both UDP-origin and TCP-origin queries."""
import os
from pathlib import Path
import select
import socket
import socketserver
import struct
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
GATEWAY = Path(os.environ.get('NETWORKSHARER_TEST_GATEWAY', ROOT/'socks_gateway'))
TOKEN = os.urandom(16).hex().encode()
PRIMARY = ('203.0.113.1', 53)
SECONDARY = ('203.0.113.77', 53)
targets = []

def readn(sock, n):
    result = b''
    while len(result) < n:
        data = sock.recv(n - len(result))
        if not data: raise EOFError()
        result += data
    return result

class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(5)
        try:
            version, count = readn(sock, 2)
            methods = readn(sock, count)
            if version != 5 or 0 not in methods: return
            sock.sendall(b'\x05\x00')
            request = readn(sock, 10)
            if request[:4] != b'\x05\x01\x00\x01': return
            target = (socket.inet_ntoa(request[4:8]), struct.unpack('!H', request[8:])[0])
            targets.append(target)
            behavior = self.server.primary_behavior if target == PRIMARY else 'success'
            if behavior == 'unreachable':
                sock.sendall(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            sock.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01')
            # Model the observed resolver path that resets a TCP connection when
            # the two-byte length prefix arrives without any query bytes.
            first = sock.recv(4098)
            if len(first) <= 2:
                self.server.prefix_only = True
                return
            n = struct.unpack('!H', first[:2])[0]
            query = first[2:]
            if len(query) < n: query += readn(sock, n-len(query))
            if behavior == 'timeout':
                time.sleep(3)
                return
            rcode = {'success': 0, 'servfail': 2, 'nxdomain': 3}[behavior]
            reply = query[:2] + bytes([0x81, 0x80 | rcode]) + query[4:]
            sock.sendall(struct.pack('!H', len(reply)) + reply)
        except (OSError, EOFError):
            pass

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    prefix_only = False
    primary_behavior = 'unreachable'

with Server(('127.0.0.1', 0), Proxy) as server:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = os.environ.copy()
    env.update(NAPTD_RELAY_TOKEN=TOKEN.decode(), NAPTD_DNS_SERVER=PRIMARY[0], NAPTD_DNS_SECONDARY=SECONDARY[0])
    gateway = subprocess.Popen([str(GATEWAY), 'socks5', str(server.server_address[1])],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    try:
        ready, _, _ = select.select([gateway.stdout], [], [], 8)
        assert ready, 'gateway startup timed out'
        line = gateway.stdout.readline().strip()
        assert line.startswith('gateway_ready:'), line
        _, tcp_port, udp_port = line.split(':')
        query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x00\x00\x01\x00\x01'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            client.sendto(b'DNS1'+TOKEN+query, ('127.0.0.1', int(udp_port)))
            response, _ = client.recvfrom(4096)
            assert response[36:38] == query[:2] and response[38:40] == b'\x81\x80'
        with socket.create_connection(('127.0.0.1', int(tcp_port)), timeout=5) as client:
            client.settimeout(5)
            client.sendall(b'NAT1'+TOKEN+socket.inet_aton('8.8.8.8')+struct.pack('!H', 53))
            client.sendall(struct.pack('!H', len(query))+query)
            n = struct.unpack('!H', readn(client, 2))[0]
            assert readn(client, n)[2:4] == b'\x81\x80'
        assert targets == [PRIMARY, SECONDARY, PRIMARY, SECONDARY], targets
        assert not server.prefix_only, 'DNS frame length was sent separately'
        for behavior, expected, expected_targets in (
            ('servfail', 0, [PRIMARY, SECONDARY]),
            ('nxdomain', 3, [PRIMARY]),
            ('timeout', 0, [PRIMARY, SECONDARY]),
        ):
            targets.clear()
            server.primary_behavior = behavior
            start = time.monotonic()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(6)
                client.sendto(b'DNS1'+TOKEN+query, ('127.0.0.1', int(udp_port)))
                response, _ = client.recvfrom(4096)
            assert response[39] & 15 == expected, behavior
            assert targets == expected_targets, (behavior, targets)
            if behavior == 'timeout': assert time.monotonic()-start < 5, 'backup took too long'
    finally:
        gateway.terminate()
        gateway.wait(timeout=5)
        server.shutdown()
        thread.join(timeout=2)

for address in ('127.127.127.5', '0.0.0.0', 'bad', '224.0.0.1'):
    env = os.environ.copy()
    env.update(NAPTD_RELAY_TOKEN=TOKEN.decode(), NAPTD_DNS_SERVER=address)
    rejected = subprocess.run([str(GATEWAY), 'direct', 'en0'], env=env,
                              capture_output=True, text=True, timeout=5)
    assert rejected.returncode == 2 and 'invalid_dns_server' in rejected.stderr
print('DNS fallback for UDP and TCP, timeout, SERVFAIL, NXDOMAIN and invalid addresses passed')
