#!/usr/bin/env python3
"""Bounded local throughput and resource check; no external network or devices."""
import asyncio
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
TOKEN = os.urandom(16).hex().encode()
BLOCK = b'X' * 65536

def process_info(pid):
    output = subprocess.check_output(['/bin/ps', '-p', str(pid), '-o', 'rss='], text=True)
    fds = subprocess.run(['/usr/sbin/lsof', '-n', '-p', str(pid)], capture_output=True, text=True)
    values={'rss_kib': int(output.strip()), 'open_files': max(0, len(fds.stdout.splitlines())-1)}
    probe=os.environ.get('NETWORKSHARER_TEST_IO_PROBE')
    if probe:
        read_bytes,written_bytes,logical_writes=map(int,subprocess.check_output([probe,str(pid)],text=True).split())
        values.update(disk_read=read_bytes,disk_written=written_bytes,logical_writes=logical_writes)
    return values

async def main():
    peers = set()
    async def proxy(reader, writer):
        peers.add(writer)
        try:
            if await reader.readexactly(3) != b'\x05\x01\x00': return
            writer.write(b'\x05\x00'); await writer.drain()
            await reader.readexactly(10)
            writer.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01'); await writer.drain()
            total = 0
            while True:
                data = await reader.read(65536)
                if not data: break
                total += len(data)
            writer.write(struct.pack('!Q', total)); await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            peers.discard(writer); writer.close()
            try: await writer.wait_closed()
            except ConnectionError: pass
    server = await asyncio.start_server(proxy, '127.0.0.1', 0, backlog=512)
    env = dict(os.environ, NAPTD_RELAY_TOKEN=TOKEN.decode())
    gateway = await asyncio.create_subprocess_exec(str(ROOT/'socks_gateway'), 'socks5',
        str(server.sockets[0].getsockname()[1]), env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        line = (await asyncio.wait_for(gateway.stdout.readline(), 8)).decode().strip()
        assert line.startswith('gateway_ready:'), line
        _, tcp, _ = line.split(':')
        before = await asyncio.to_thread(process_info, gateway.pid)
        async def transfer(size):
            reader, writer = await asyncio.open_connection('127.0.0.1', int(tcp))
            try:
                writer.write(b'NAT1'+TOKEN+socket.inet_aton('203.0.113.55')+struct.pack('!H', 8080))
                for _ in range(size//len(BLOCK)):
                    writer.write(BLOCK)
                    await writer.drain()
                writer.write_eof()
                amount = struct.unpack('!Q', await reader.readexactly(8))[0]
                assert amount == size
            finally:
                writer.close(); await writer.wait_closed()
        for concurrency, size in ((1,256*1024*1024),(16,16*1024*1024),(64,4*1024*1024)):
            start = time.monotonic()
            await asyncio.wait_for(asyncio.gather(*(transfer(size) for _ in range(concurrency))), 30)
            elapsed = time.monotonic()-start
            print(f'connections={concurrency} bytes={concurrency*size} seconds={elapsed:.3f} '
                  f'mbps={concurrency*size*8/elapsed/1_000_000:.1f}', flush=True)
        # Repeated short sessions test resource recovery independently of speed.
        for _ in range(10): await asyncio.gather(*(transfer(65536) for _ in range(20)))
        duration=int(sys.argv[1]) if len(sys.argv)>1 else 0
        if duration:
            deadline=time.monotonic()+min(max(duration,1),120); rounds=0
            while time.monotonic()<deadline:
                await asyncio.gather(*(transfer(65536) for _ in range(10)))
                rounds+=1
                await asyncio.sleep(.1)
            print(f'soak_seconds={duration} short_connections={rounds*10}',flush=True)
        await asyncio.sleep(2)
        after = await asyncio.to_thread(process_info, gateway.pid)
        print(f'resources_before={before} resources_after={after}', flush=True)
        assert after['open_files'] <= before['open_files']+8, 'open descriptors did not return near baseline'
        if os.environ.get('NETWORKSHARER_TEST_LEAKS')=='1':
            scan=await asyncio.to_thread(subprocess.run,['/usr/bin/leaks','-q','--noContent','--nostacks',str(gateway.pid)],
                                         capture_output=True,text=True,timeout=30)
            summaries=[line.strip() for line in scan.stdout.splitlines() if re.search(r'\b[0-9]+ leaks? for\b',line)]
            print('leak_scan_exit='+str(scan.returncode)+' '+(' '.join(summaries) or 'no summary'),flush=True)
            assert scan.returncode==0,'leak scanner reported leaks or could not inspect the process'
    finally:
        for writer in list(peers): writer.close()
        server.close(); await server.wait_closed()
        if gateway.returncode is None: gateway.terminate()
        await asyncio.wait_for(gateway.wait(), 8)

asyncio.run(main())
