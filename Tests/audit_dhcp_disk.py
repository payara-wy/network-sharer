#!/usr/bin/env python3
"""Read-only isolated duplicate-DHCP/write-amplification test, no admin/root."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'build/audit-20261120-readonly'
spec=importlib.util.spec_from_file_location('packets',ROOT/'Tests/test_standalone_packets.py')
packets=importlib.util.module_from_spec(spec)
spec.loader.exec_module(packets)
bridge=ROOT/'build/stability-20261120-140910/局域网代理共享器.app/Contents/MacOS/standalone_bridge'
assert bridge.is_file()
result={}
with tempfile.TemporaryDirectory(prefix='dhcp-write-audit-',dir=OUT/'test') as directory:
    work=Path(directory)
    leases=work/'leases';leases.mkdir(mode=0o700)
    macs=work/'host-macs';macs.write_text('aa:bb:cc:dd:ee:f0\n');macs.chmod(0o600)
    host,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    proc=subprocess.Popen([str(bridge),'--fd',str(child.fileno()),'--lease-dir',str(leases)],
        env=dict(os.environ,NAPTD_HOST_MAC_FILE=str(macs),TMPDIR=str(work)),pass_fds=[child.fileno()],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    child.close()
    try:
        assert proc.stdout.readline().strip()=='bridge_ready',proc.stderr.read()
        host.settimeout(5)
        mac=bytes.fromhex('024e53000001')
        frame=packets.discover(mac,42)
        start=time.monotonic();inos=[]
        for index in range(64):
            host.send(frame);response=host.recv(65536)
            assert response[14+20+8+236:14+20+8+240]==b'\x63\x82\x53\x63'
            assert (leases/'dhcp-leases-v2.bin').is_file()
            stat=(leases/'dhcp-leases-v2.bin').stat();inos.append(stat.st_ino)
        elapsed=time.monotonic()-start
        result={'duplicate_requests':64,'responses':64,'unique_inodes':len(set(inos)),
                'file_size_bytes':stat.st_size,'seconds':elapsed,
                'replacements_per_second':64/elapsed,
                'payload_mib_per_second':64*stat.st_size/elapsed/1048576,
                'source':'build/stability-20261120-140910/.../standalone_bridge',
                'production_lease_path_untouched':True}
        assert len(set(inos))==64,inos
    finally:
        proc.terminate()
        try:proc.wait(timeout=3)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
        result['stderr']=proc.stderr.read();proc.stdout.close();proc.stderr.close();host.close()
report=OUT/'evidence/dhcp-write-result.json'
report.write_text(json.dumps(result,indent=2))
print(json.dumps(result,indent=2))
