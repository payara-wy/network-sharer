#!/usr/bin/env python3
"""Packet-level DHCP smoke test for the isolated standalone prototype."""
import ipaddress
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
BRIDGE=Path(os.environ.get('NETWORKSHARER_TEST_BRIDGE',str(ROOT/'build/standalone-prototype/standalone_bridge')))

def host_filter_env():
    directory=tempfile.TemporaryDirectory(prefix='networksharer-hostmac-',dir='/private/tmp')
    path=Path(directory.name)/'host-macs'
    path.write_text('aa:bb:cc:dd:ee:f0\n')
    path.chmod(0o600)
    return dict(os.environ,NAPTD_HOST_MAC_FILE=str(path)),directory

def checksum(data):
    if len(data)%2: data+=b'\0'
    total=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while total>>16: total=(total&0xffff)+(total>>16)
    return (~total)&0xffff

def discover(mac,xid):
    dhcp=bytearray(300)
    dhcp[0:4]=bytes([1,1,6,0]); dhcp[4:8]=struct.pack('!I',xid)
    dhcp[10:12]=b'\x80\x00'; dhcp[28:34]=mac; dhcp[236:240]=b'\x63\x82\x53\x63'
    dhcp[240:244]=b'\x35\x01\x01\xff'
    udp=struct.pack('!HHHH',68,67,8+len(dhcp),0)+dhcp
    ip=bytearray(struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),0,0,64,17,0,b'\0'*4,b'\xff'*4))
    ip[10:12]=struct.pack('!H',checksum(ip))
    return b'\xff'*6+mac+b'\x08\x00'+ip+udp

def main():
    host,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    env,directory=host_filter_env()
    proc=subprocess.Popen([str(BRIDGE),'--fd',str(child.fileno())],env=env,pass_fds=[child.fileno()],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    child.close()
    try:
        assert proc.stdout.readline().strip()==b'bridge_ready',proc.stderr.read()
        host.settimeout(3)
        addresses=[]
        for number in range(243):
            mac=bytes.fromhex('024e53')+number.to_bytes(3,'big'); xid=1234567+number
            host.send(discover(mac,xid))
            response=host.recv(65536)
            assert response[12:14]==b'\x08\x00'
            ip=response[14:]; ihl=(ip[0]&15)*4; udp=ip[ihl:]; dhcp=udp[8:]
            assert struct.unpack('!HH',udp[:4])==(67,68)
            assert dhcp[0]==2 and dhcp[4:8]==struct.pack('!I',xid) and dhcp[28:34]==mac
            assert dhcp[236:243]==b'\x63\x82\x53\x63\x35\x01\x02'
            addresses.append(ipaddress.IPv4Address(dhcp[16:20]))
        assert len(set(addresses))==243
        assert addresses[0]==ipaddress.IPv4Address('172.30.79.10')
        assert addresses[-1]==ipaddress.IPv4Address('172.30.79.252')
        print('DHCP discovery produced 243 distinct offers')
    finally:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        host.close()
        directory.cleanup()
        if proc.returncode not in (0,-15): print(proc.stderr.read().decode(errors='replace'))

if __name__=='__main__': main()
