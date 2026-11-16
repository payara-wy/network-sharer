#!/usr/bin/env python3
"""Keep TCP connections busy and ensure DNS still has reserved capacity."""
import asyncio
import os
from pathlib import Path
import socket
import struct

ROOT = Path(__file__).resolve().parents[1]
TOKEN = os.urandom(16).hex().encode()
TCP_COUNT = 192

async def main():
    connected = 0
    ready = asyncio.Event()
    peers = set()
    async def proxy(reader, writer):
        nonlocal connected
        peers.add(writer)
        try:
            assert await reader.readexactly(3) == b'\x05\x01\x00'
            writer.write(b'\x05\x00'); await writer.drain()
            request = await reader.readexactly(10)
            port = struct.unpack('!H', request[8:10])[0]
            writer.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01'); await writer.drain()
            if port == 53:
                n = struct.unpack('!H', await reader.readexactly(2))[0]
                query = await reader.readexactly(n)
                reply = query[:2]+b'\x81\x80'+query[4:]
                writer.write(struct.pack('!H', len(reply))+reply); await writer.drain()
            else:
                connected += 1
                if connected == TCP_COUNT: ready.set()
                await reader.read()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            peers.discard(writer); writer.close()
            try: await writer.wait_closed()
            except ConnectionError: pass
    server = await asyncio.start_server(proxy, '127.0.0.1', 0, backlog=512)
    env = dict(os.environ, NAPTD_RELAY_TOKEN=TOKEN.decode(), NAPTD_DNS_SERVER='203.0.113.77')
    gateway = await asyncio.create_subprocess_exec(str(ROOT/'socks_gateway'), 'socks5',
        str(server.sockets[0].getsockname()[1]), env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    clients = []
    try:
        line = (await asyncio.wait_for(gateway.stdout.readline(), 8)).decode().strip()
        assert line.startswith('gateway_ready:'), line
        _, tcp, udp = line.split(':')
        semaphore = asyncio.Semaphore(32)
        async def connect_one():
            async with semaphore:
                _, writer = await asyncio.open_connection('127.0.0.1', int(tcp))
                clients.append(writer)
                writer.write(b'NAT1'+TOKEN+socket.inet_aton('203.0.113.55')+struct.pack('!H', 8080))
                await writer.drain()
        await asyncio.gather(*(connect_one() for _ in range(TCP_COUNT)))
        await asyncio.wait_for(ready.wait(), 20)
        query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x00\x00\x01\x00\x01'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
            dns.settimeout(5)
            dns.sendto(b'DNS1'+TOKEN+query, ('127.0.0.1', int(udp)))
            reply, _ = await asyncio.to_thread(dns.recvfrom, 4096)
            assert reply[36:40] == query[:2]+b'\x81\x80'
        # The 193rd TCP session is deliberately rejected at the configured cap.
        overflow_reader, overflow = await asyncio.open_connection('127.0.0.1', int(tcp))
        overflow.write(b'NAT1'+TOKEN+socket.inet_aton('203.0.113.55')+struct.pack('!H', 8080))
        await overflow.drain()
        try: assert await asyncio.wait_for(overflow_reader.read(1), 5) == b''
        except ConnectionResetError: pass
        overflow.close()
        try: await overflow.wait_closed()
        except (ConnectionResetError, BrokenPipeError): pass
        # A freed slot must be reusable without restarting the gateway.
        clients[0].close(); await clients[0].wait_closed()
        deadline = asyncio.get_running_loop().time()+8
        while connected == TCP_COUNT and asyncio.get_running_loop().time()<deadline:
            await asyncio.sleep(.1)
            await connect_one()
        assert connected > TCP_COUNT, 'TCP capacity did not recover after a client disconnected'
        print(f'DNS answered with {TCP_COUNT} TCP connections; overflow rejected and capacity recovered')
    finally:
        for writer in clients: writer.close()
        for writer in list(peers): writer.close()
        server.close(); await server.wait_closed()
        if gateway.returncode is None: gateway.terminate()
        await asyncio.wait_for(gateway.wait(), 8)

asyncio.run(main())
