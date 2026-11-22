#!/usr/bin/env python3
"""Compare duplicate DHCP write amplification before/after the lease change.

Isolated --fd core, a disposable lease directory, no admin or production leases.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('packets',ROOT/'Tests/test_standalone_packets.py')
packets=importlib.util.module_from_spec(spec); spec.loader.exec_module(packets)


def workload(binary, count):
    with tempfile.TemporaryDirectory(prefix='lease-write-',dir=ROOT/'build') as temp:
        work=Path(temp); leases=work/'leases'; leases.mkdir(mode=0o700)
        macs=work/'host-macs'; macs.write_text('aa:bb:cc:dd:ee:f0\n'); macs.chmod(0o600)
        host,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
        proc=subprocess.Popen([str(binary),'--fd',str(child.fileno()),'--lease-dir',str(leases)],
            env=dict(os.environ,NAPTD_HOST_MAC_FILE=str(macs),TMPDIR=str(work)),pass_fds=[child.fileno()],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        child.close()
        try:
            assert proc.stdout.readline().strip()=='bridge_ready',proc.stderr.read()
            host.settimeout(5)
            frame=packets.discover(bytes.fromhex('024e53000001'),42)
            inodes=[]; start=time.monotonic()
            for _ in range(count):
                host.send(frame); assert host.recv(65536)
                state=leases/'dhcp-leases-v2.bin'
                inodes.append(state.stat().st_ino)
            elapsed=time.monotonic()-start
            size=(leases/'dhcp-leases-v2.bin').stat().st_size
            return {'requests':count,'responses':count,'unique_file_replacements':len(set(inodes)),
                    'seconds':round(elapsed,4),'replacements_per_second':round(count/elapsed,1),
                    'payload_mib_per_second':round(count*size/elapsed/1048576,2),
                    'file_size':size,'lease_sha256':hashlib.sha256((leases/'dhcp-leases-v2.bin').read_bytes()).hexdigest()}
        finally:
            proc.terminate()
            try: proc.wait(timeout=3)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
            assert 'AddressSanitizer' not in proc.stderr.read()
            proc.stdout.close(); proc.stderr.close(); host.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('binary',type=Path)
    parser.add_argument('--count',type=int,default=64); args=parser.parse_args()
    report={key:workload(args.binary,args.count) for key in ('first','second')}
    print(json.dumps(report,indent=2))
