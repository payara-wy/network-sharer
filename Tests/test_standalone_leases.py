#!/usr/bin/env python3
"""Isolated packet tests for crash-safe leases and fail-closed state loading."""
import ipaddress
import hashlib
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
from test_standalone_packets import BRIDGE, discover, host_filter_env

host_env,host_directory=host_filter_env()


def start(directory):
    parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    proc=subprocess.Popen([str(BRIDGE),'--fd',str(child.fileno()),'--lease-dir',str(directory)],
                          env=host_env,pass_fds=[child.fileno()],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    child.close(); parent.settimeout(3)
    return parent,proc

def offer(sock,mac,xid):
    sock.send(discover(mac,xid)); response=sock.recv(65536)
    ip=response[14:]; udp=ip[(ip[0]&15)*4:]; dhcp=udp[8:]
    assert dhcp[0]==2 and dhcp[4:8]==struct.pack('!I',xid) and dhcp[28:34]==mac
    assert dhcp[236:243]==b'\x63\x82\x53\x63\x35\x01\x02'
    return ipaddress.IPv4Address(dhcp[16:20])

def ack(sock,mac,xid,address):
    frame=bytearray(discover(mac,xid)); start=14+20+8+240
    opt=b'\x35\x01\x03\x32\x04'+address.packed+b'\x36\x04'+ipaddress.IPv4Address('172.30.79.1').packed+b'\xff'
    frame[start:start+len(opt)]=opt
    sock.send(frame); response=sock.recv(65536)
    ip=response[14:]; dhcp=ip[(ip[0]&15)*4+8:]
    assert dhcp[236:243]==b'\x63\x82\x53\x63\x35\x01\x05'
    assert dhcp[16:20]==address.packed

def stop(sock,proc,kill=False):
    if kill: proc.kill()
    else: proc.terminate()
    proc.wait(timeout=5); sock.close()

with tempfile.TemporaryDirectory(prefix='networksharer-lease-test-',dir='/private/tmp') as temp:
    path=Path(temp); assert os.stat(path).st_mode&0o077==0
    a=bytes.fromhex('024e53000001'); b=bytes.fromhex('024e53000002')
    sock,proc=start(path); assert proc.stdout.readline()==b'bridge_ready\n'
    address=offer(sock,a,100); ack(sock,a,101,address)
    assert (path/'dhcp-leases-v2.bin').is_file()
    other,conflict=start(path); assert conflict.wait(timeout=4)!=0; other.close()
    stop(sock,proc,True)
    abandoned=path/'.lease-0123abcd-9876abcd'; abandoned.write_bytes(b'partial')
    sock,proc=start(path); assert proc.stdout.readline()==b'bridge_ready\n'
    assert not abandoned.exists()
    assert offer(sock,b,102)!=address
    assert offer(sock,a,103)==address
    stop(sock,proc)
    state=path/'dhcp-leases-v2.bin'
    raw=bytearray(state.read_bytes())
    # An expired first lease is reusable while the second remains reserved.
    raw[16+1+2+2+6:16+1+2+2+6+4]=struct.pack('!I',1)
    raw[-32:]=hashlib.sha256(raw[:-32]).digest(); state.write_bytes(raw)
    sock,proc=start(path); assert proc.stdout.readline()==b'bridge_ready\n'
    c=bytes.fromhex('024e53000003')
    assert offer(sock,c,104)==address
    assert offer(sock,b,105)!=address
    stop(sock,proc)
    raw=bytearray(state.read_bytes()); raw[40]^=1; state.write_bytes(raw)
    sock,proc=start(path); assert proc.wait(timeout=4)!=0; assert proc.stdout.read()==b''; sock.close()
    state.unlink(); state.symlink_to('/etc/passwd')
    sock,proc=start(path); assert proc.wait(timeout=4)!=0; sock.close()
    print('Lease survives SIGKILL, expiry is reused, and unsafe state is rejected')
host_directory.cleanup()
