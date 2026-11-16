#!/usr/bin/env python3
"""Exercise the actual local validation against small loopback SOCKS servers."""
import socket
import socketserver
import subprocess
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT/'Sources/HotspotLab.swift').read_text()
helper = source[source.index('enum CheckLevel {'):source.index('@MainActor final class HotspotModel')]
driver = r'''
import Foundation
import Darwin
import SystemConfiguration
''' + helper + r'''
if CommandLine.arguments[1] == "dns" {
    print(validDNSServer(CommandLine.arguments[2]) ? "valid" : "invalid")
} else {
    let level: CheckLevel
    if CommandLine.arguments[1] == "dnsprobe" {
        (level, _) = checkDNSResponse(server: CommandLine.arguments[2], source: "en0",
                                      proxyPort: Int(CommandLine.arguments[3])!, gatewayPath: CommandLine.arguments[4])
    } else {
        let port = Int(CommandLine.arguments[2])!
        (level, _) = checkSOCKSMethod(port: port, requiresAuthentication: CommandLine.arguments[3] == "auth")
    }
    switch level {
    case .good: print("good")
    case .attention: print("attention")
    case .pending: print("pending")
    }
}
'''

class Server(socketserver.TCPServer):
    allow_reuse_address = True
    def __init__(self, response):
        self.response = response
        self.observed = []
        self.extra = []
        super().__init__(('127.0.0.1', 0), Handler)

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        greeting = self.request.recv(3)
        self.server.observed.append(greeting)
        self.request.sendall(bytes([5, self.server.response]))
        # The status check must not send the actual password or start a proxy session.
        self.server.extra.append(self.request.recv(32))

def readn(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length-len(data))
        if not chunk: raise EOFError()
        data += chunk
    return data

class DNSProxy(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(5)
        try:
            assert readn(sock, 3) == b'\x05\x01\x00'
            sock.sendall(b'\x05\x00')
            request = readn(sock, 10)
            assert request[:4] == b'\x05\x01\x00\x01'
            self.server.destinations.append(socket.inet_ntoa(request[4:8]))
            sock.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01')
            length = int.from_bytes(readn(sock, 2), 'big')
            query = readn(sock, length)
            if self.server.success:
                response = query[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+query[12:]+b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04'
            else:
                response = query[:2]+b'\x81\x83'+query[4:]
            sock.sendall(len(response).to_bytes(2, 'big')+response)
        except (EOFError, OSError):
            pass

class DNSProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    def __init__(self, success):
        self.success = success
        self.destinations = []
        super().__init__(('127.0.0.1', 0), DNSProxy)

with tempfile.TemporaryDirectory(prefix='hotspot-local-check-', dir='/private/tmp') as tmp:
    script, binary = Path(tmp)/'probe.swift', Path(tmp)/'probe'
    script.write_text(driver)
    subprocess.run(['/usr/bin/swiftc', '-module-cache-path', '/private/tmp/hotspot-swift-cache',
                    '-Xcc', '-fmodules-cache-path=/private/tmp/hotspot-swift-cache', str(script), '-o', str(binary)], check=True)
    def run(*args):
        return subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True, check=True, timeout=5).stdout.strip()
    for value in ('1.1.1.1', '223.5.5.5', '192.168.1.1'):
        assert run('dns', value) == 'valid', value
    for value in ('bad', '127.127.127.5', '0.0.0.0', '224.0.0.1', '1.2.3.999'):
        assert run('dns', value) == 'invalid', value
    for response, mode, expected, method in ((0, 'none', 'good', 0), (2, 'auth', 'good', 2), (255, 'auth', 'attention', 2)):
        with Server(response) as server:
            thread = threading.Thread(target=server.handle_request, daemon=True)
            thread.start()
            assert run('socks', server.server_address[1], mode) == expected
            thread.join(timeout=5)
            assert server.observed == [bytes([5, 1, method])]
            assert server.extra == [b'']
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    assert run('socks', port, 'none') == 'attention'
    for success, expected in ((True, 'good'), (False, 'attention')):
        with DNSProxyServer(success) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            assert run('dnsprobe', '203.0.113.77', server.server_address[1], ROOT/'socks_gateway') == expected
            assert server.destinations == ['203.0.113.77']
            server.shutdown()
            thread.join(timeout=2)
print('Local checks: DNS validation and live response, SOCKS availability and authentication negotiation passed')
