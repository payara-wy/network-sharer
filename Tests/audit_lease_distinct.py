#!/usr/bin/env python3
"""Prove lease dedup still persists every distinct lease change and reloads it."""
import importlib.util
import ipaddress
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('packets',ROOT/'Tests/test_standalone_packets.py')
packets=importlib.util.module_from_spec(spec); spec.loader.exec_module(packets)


def parse(response):
    ip=response[14:]; dhcp=ip[(ip[0]&15)*4+8:]
    return dhcp


def start(binary, leases, macs):
    host,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    proc=subprocess.Popen([str(binary),'--fd',str(child.fileno()),'--lease-dir',str(leases)],
        env=dict(os.environ,NAPTD_HOST_MAC_FILE=str(macs)),pass_fds=[child.fileno()],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    child.close(); host.settimeout(5)
    assert proc.stdout.readline().strip()=='bridge_ready',proc.stderr.read()
    return host,proc


def stop(host,proc):
    proc.terminate()
    try: proc.wait(timeout=3)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait()
    host.close()


def discover(host,mac,xid):
    host.send(packets.discover(mac,xid)); response=host.recv(65536)
    dhcp=parse(response)
    assert dhcp[0]==2 and dhcp[4:8]==struct.pack('!I',xid) and dhcp[28:34]==mac
    return ipaddress.IPv4Address(dhcp[16:20])


def request(host,mac,xid,address):
    frame=bytearray(packets.discover(mac,xid)); offset=14+20+8+240
    option=b'\x35\x01\x03\x32\x04'+address.packed+b'\x36\x04'+ipaddress.IPv4Address('172.30.79.1').packed+b'\xff'
    frame[offset:offset+len(option)]=option
    host.send(frame); response=host.recv(65536)
    dhcp=parse(response)
    assert dhcp[236:243]==b'\x63\x82\x53\x63\x35\x01\x05', dhcp[236:243]
    assert dhcp[16:20]==address.packed
    return dhcp


def inode(leases): return (leases/'dhcp-leases-v2.bin').stat().st_ino


with tempfile.TemporaryDirectory(prefix='lease-distinct-',dir=ROOT/'build') as temp:
    work=Path(temp); leases=work/'leases'; leases.mkdir(mode=0o700)
    macs=work/'host-macs'; macs.write_text('aa:bb:cc:dd:ee:f0\n'); macs.chmod(0o600)
    a=bytes.fromhex('024e53000001'); b=bytes.fromhex('024e53000002')
    binary=Path(os.environ['REPAIR_BRIDGE'])
    report={}

    host,proc=start(binary,leases,macs)
    try:
        offer_a=discover(host,a,10)
        first=inode(leases)
        # A repeated identical discover must not write again.
        assert discover(host,a,11)==offer_a
        assert inode(leases)==first
        # A second client is a distinct lease table and must be persisted.
        offer_b=discover(host,b,12)
        assert offer_b!=offer_a
        after_b=inode(leases)
        assert after_b!=first, 'distinct lease was not persisted'
        # Committing A (an ACK changes expiry/state) must persist again.
        request(host,a,13,offer_a)
        after_ack=inode(leases)
        assert after_ack!=after_b, 'lease acknowledgement was not persisted'
        report['deduped_repeat']=True
        report['distinct_lease_written']=True
        report['ack_written']=True
    finally: stop(host,proc)

    # Reload proves the on-disk snapshot contains both leases and A's ACK.
    host,proc=start(binary,leases,macs)
    try:
        assert discover(host,a,14)==offer_a, 'stored lease for A was lost'
        assert discover(host,b,15)==offer_b, 'stored lease for B was lost'
        report['reload_restored_both']=True
    finally: stop(host,proc)

    print(report)
