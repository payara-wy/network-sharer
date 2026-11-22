#!/usr/bin/env python3
"""Verify the built gateway forwards UDP through the real local SOCKS5 upstream.

One fixed DNS query, no browsing data, no credentials beyond the test file the
gateway itself receives. Uses a LAN listener on the current Wi-Fi address.
"""
import os
import select
import socket
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATEWAY = os.environ.get('VERIFY_GATEWAY', os.path.join(ROOT, 'build', 'gateway-real-udp'))
ADDRESS = subprocess.check_output(['/usr/sbin/ipconfig', 'getifaddr', 'en0'], text=True).strip()
UPSTREAM = int(sys.argv[1]) if len(sys.argv) > 1 else 1082


def recvn(sock, n):
    data = b''
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise EOFError()
        data += part
    return data


def main():
    with socket.socket() as probe:
        probe.bind((ADDRESS, 0))
        port = probe.getsockname()[1]
    with tempfile.TemporaryDirectory(dir=os.path.join(ROOT, 'build')) as work:
        auth = os.path.join(work, 'auth')
        with open(auth, 'wb') as handle:
            handle.write(bytes([6]) + b'client' + bytes([7]) + b'testkey')
        env = {k: v for k, v in os.environ.items() if not k.startswith('NAPTD_')}
        env.update(NAPTD_RELAY_TOKEN='a' * 32, NAPTD_DNS_SERVER='1.1.1.1',
                   NAPTD_LAN_PORT=str(port), NAPTD_LAN_INTERFACE='en0', NAPTD_LAN_AUTH_FILE=auth)
        proc = subprocess.Popen([GATEWAY, 'socks5', str(UPSTREAM)], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        control = udp = None
        try:
            if not select.select([proc.stdout], [], [], 8)[0]:
                raise RuntimeError('gateway did not start: ' + proc.stderr.read()[:300])
            line = proc.stdout.readline().strip()
            assert line.startswith('gateway_ready:'), line
            control = socket.create_connection((ADDRESS, port), timeout=5)
            control.settimeout(6)
            control.sendall(b'\x05\x01\x02')
            assert recvn(control, 2) == b'\x05\x02'
            control.sendall(bytes([1, 6]) + b'client' + bytes([7]) + b'testkey')
            assert recvn(control, 2) == b'\x01\x00'
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind((ADDRESS, 0))
            udp.settimeout(6)
            control.sendall(b'\x05\x03\x00\x01' + socket.inet_aton(ADDRESS)
                            + struct.pack('!H', udp.getsockname()[1]))
            reply = recvn(control, 10)
            assert reply[:2] == b'\x05\x00', reply
            relay = (socket.inet_ntoa(reply[4:8]), struct.unpack('!H', reply[8:])[0])
            query = (b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                     b'\x07example\x03com\x00\x00\x01\x00\x01')
            answered = False
            # Public resolvers are occasionally slow through the upstream; try
            # several fixed targets and repeat once before calling it unsupported.
            for server in ('8.8.8.8', '1.1.1.1', '223.5.5.5'):
                header = b'\x00\x00\x00\x01' + socket.inet_aton(server) + struct.pack('!H', 53)
                for _ in range(2):
                    udp.sendto(header + query, relay)
                    try:
                        data, _ = udp.recvfrom(4096)
                    except socket.timeout:
                        continue
                    if (data[:10] == header and data[10:12] == query[:2]
                            and data[12] & 0x80 and data[14:16] != b'\x00\x00'):
                        print('REAL UPSTREAM UDP: ok via', relay, 'server', server,
                              'answer bytes', len(data) - 10)
                        answered = True
                        break
                if answered:
                    break
            assert answered, 'no valid DNS reply from any target'
        finally:
            if control:
                control.close()
            if udp:
                udp.close()
            proc.terminate()
            proc.wait(timeout=5)
            stderr = proc.stderr.read()
            if 'AddressSanitizer' in stderr or 'runtime error:' in stderr:
                raise RuntimeError(stderr[:300])


if __name__ == '__main__':
    main()
