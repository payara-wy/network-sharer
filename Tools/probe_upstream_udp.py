#!/usr/bin/env python3
"""Small, explicit SOCKS5 UDP capability probe; no browsing data or credentials."""
import argparse
import json
import socket
import struct
import time
from pathlib import Path


def readn(sock, size):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError('SOCKS control connection closed')
        data += chunk
    return data


def query_packet():
    identifier = __import__('os').urandom(2)
    question = b'\x07example\x03com\x00\x00\x01\x00\x01'
    return identifier + struct.pack('!HHHHH', 0x0100, 1, 0, 0, 0) + question


def verify_dns(payload, query):
    return (len(payload) >= len(query) and payload[:2] == query[:2]
            and payload[2] & 0x80 and (payload[3] & 15) == 0
            and payload[4:6] == b'\x00\x01' and payload[6:8] != b'\x00\x00'
            and payload[12:len(query)] == query[12:])


def associate(control, endpoint):
    control.sendall(b'\x05\x01\x00')
    if readn(control, 2) != b'\x05\x00':
        raise RuntimeError('No-auth method not accepted; credentials were not accessed')
    control.sendall(b'\x05\x03\x00\x01' + socket.inet_aton(endpoint[0]) + struct.pack('!H', endpoint[1]))
    header = readn(control, 4)
    if header[:3] != b'\x05\x00\x00':
        raise RuntimeError('UDP ASSOCIATE rejected: ' + header.hex())
    if header[3] == 1:
        address = socket.inet_ntoa(readn(control, 4))
    elif header[3] == 3:
        address = readn(control, readn(control, 1)[0]).decode('ascii')
    else:
        raise RuntimeError('Non-IPv4 relay not supported by this probe')
    port = struct.unpack('!H', readn(control, 2))[0]
    if address == '0.0.0.0':
        address = control.getpeername()[0]
    if not port:
        raise RuntimeError('Invalid relay port')
    # Only contact the local service this diagnostic was asked to test.
    if address not in ('localhost', '127.0.0.1'):
        raise RuntimeError('Relay is not loopback: ' + address)
    return address, port


def probe(port):
    result = {'upstream': '127.0.0.1:' + str(port), 'associate': False, 'datagrams': [], 'supported': False}
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=5) as control:
            control.settimeout(5)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.bind(('127.0.0.1', 0))
                relay = associate(control, udp.getsockname())
                result.update(associate=True, relay='%s:%s' % relay)
                udp.settimeout(5)
                udp.connect(relay)
                for server in ('1.1.1.1', '8.8.8.8'):
                    query = query_packet()
                    header = b'\x00\x00\x00\x01' + socket.inet_aton(server) + struct.pack('!H', 53)
                    started = time.monotonic()
                    udp.send(header + query)
                    try:
                        response = udp.recv(65535)
                        ok = response[:10] == header and verify_dns(response[10:], query)
                        result['datagrams'].append({'destination': server + ':53', 'valid_dns_reply': bool(ok),
                                                    'milliseconds': round((time.monotonic() - started) * 1000)})
                    except OSError as error:
                        result['datagrams'].append({'destination': server + ':53', 'error': str(error)})
                result['supported'] = any(item.get('valid_dns_reply') for item in result['datagrams'])
    except (OSError, EOFError, RuntimeError) as error:
        result['error'] = str(error)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=1082)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    result = probe(args.port)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.report:
        with args.report.open('x') as out:
            out.write(text + '\n')
    print(text)
    raise SystemExit(0 if result['supported'] else 1)
