#!/usr/bin/env python3
"""Exercise Ethernet to local relay to Ethernet without changing host networking."""
import os, select, socket, struct, subprocess
from pathlib import Path
from test_standalone_packets import checksum, discover, host_filter_env

ROOT=Path(__file__).resolve().parents[1]
BRIDGE=Path(os.environ.get('NETWORKSHARER_TEST_BRIDGE',str(ROOT/'build/standalone-prototype/standalone_bridge')))
TOKEN='0123456789abcdef0123456789abcdef'
MAC=bytes.fromhex('024e53000001')
SRC=socket.inet_aton('172.30.79.10'); DST=socket.inet_aton('8.8.8.8')

def packet(proto,body,dst=DST):
    ip=bytearray(struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(body),0,0,64,proto,0,SRC,dst))
    ip[10:12]=struct.pack('!H',checksum(ip))
    return bytes.fromhex('5255004e0101')+MAC+b'\x08\x00'+ip+body

def tcp_packet(seq,ack,flags,payload=b''):
    hdr=bytearray(struct.pack('!HHIIBBHHH',12345,443,seq,ack,0x50,flags,65535,0,0))
    pseudo=SRC+DST+struct.pack('!BBH',0,6,len(hdr)+len(payload))
    hdr[16:18]=struct.pack('!H',checksum(pseudo+hdr+payload))
    return packet(6,hdr+payload)

def get_tcp(sock):
    for _ in range(10):
        raw=sock.recv(65536)
        if raw[12:14]==b'\x08\x00':
            ip=raw[14:]; ihl=(ip[0]&15)*4
            if ip[9]==6:
                tcp=ip[ihl:]; return struct.unpack('!HHIIBBHHH',tcp[:20]),tcp[(tcp[12]>>4)*4:]
    raise AssertionError('no TCP packet')

def main():
    listen=socket.socket(); listen.bind(('127.0.0.1',0)); listen.listen()
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.bind(('127.0.0.1',0))
    host,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM); host.settimeout(4); listen.settimeout(4); udp.settimeout(4)
    env,directory=host_filter_env()
    env.update(NAPTD_RELAY_TCP=str(listen.getsockname()[1]),NAPTD_RELAY_DNS=str(udp.getsockname()[1]),NAPTD_RELAY_TOKEN=TOKEN,NAPTD_RELAY_MODE='direct')
    proc=subprocess.Popen([str(BRIDGE),'--fd',str(child.fileno())],env=env,pass_fds=[child.fileno()],stdout=subprocess.PIPE,stderr=None if os.getenv('NS_DEBUG') else subprocess.PIPE)
    child.close(); upstream=None
    try:
        assert proc.stdout.readline().strip()==b'bridge_ready'
        host.send(discover(MAC,42)); host.recv(65536)
        host.send(tcp_packet(1000,0,2))
        upstream,_=listen.accept(); upstream.settimeout(4)
        received=b''
        while len(received)<42: received+=upstream.recv(42-len(received))
        assert received==b'NAT1'+TOKEN.encode()+DST+struct.pack('!H',443),received
        header,payload=get_tcp(host); assert header[5]&0x12==0x12,header
        serverseq=header[2]; host.send(tcp_packet(1001,serverseq+1,0x10))
        host.send(tcp_packet(1001,serverseq+1,0x18,b'clientdata'))
        assert upstream.recv(100)==b'clientdata'
        # Queue a later TCP segment before its predecessor, then verify that
        # the relay receives the data in order.  This exercises reassembly.
        host.send(tcp_packet(1016,serverseq+1,0x18,b'world'))
        host.send(tcp_packet(1011,serverseq+1,0x18,b'hello'))
        reordered=b''
        while len(reordered)<10:
            part=upstream.recv(10-len(reordered))
            assert part
            reordered+=part
        assert reordered==b'helloworld',reordered
        upstream.sendall(b'serverdata')
        for _ in range(8):
            header,payload=get_tcp(host)
            if payload==b'serverdata': break
        assert payload==b'serverdata',payload
        print('slirp TCP packet path and asynchronous NAT1 relay passed')
        raw_udp=struct.pack('!HHHH',20000,1234,12,0)+b'ping'
        host.send(packet(17,raw_udp))
        request,peer=udp.recvfrom(65536)
        assert request==b'UDP1'+TOKEN.encode()+DST+struct.pack('!H',1234)+b'ping',request
        udp.sendto(request[:42]+b'pong',peer)
        for _ in range(12):
            raw=host.recv(65536)
            if raw[12:14]!=b'\x08\x00': continue
            ip=raw[14:]; ihl=(ip[0]&15)*4
            if ip[9]==17:
                body=ip[ihl:struct.unpack('!H',ip[2:4])[0]]
                if body[8:]==b'pong': break
        else: raise AssertionError('no UDP response')
        assert struct.unpack('!HH',body[:4])==(1234,20000)
        print('slirp UDP packet path and relay response passed')
        dns_a=b'\x00\x01'+b'\x00'*10; dns_b=b'\x00\x02'+b'\x00'*10
        alternate=socket.inet_aton('1.1.1.1')
        host.send(packet(17,struct.pack('!HHHH',30000,53,20,0)+dns_a))
        host.send(packet(17,struct.pack('!HHHH',30000,53,20,0)+dns_b,alternate))
        req_a,peer_a=udp.recvfrom(65536); req_b,peer_b=udp.recvfrom(65536)
        assert req_a==b'DNS1'+TOKEN.encode()+dns_a
        assert req_b==b'DNS1'+TOKEN.encode()+dns_b
        assert peer_a!=peer_b, 'destination flows must not share a relay socket'
        udp.sendto(req_b,peer_b); udp.sendto(req_a,peer_a)
        answers={}
        for _ in range(12):
            raw=host.recv(65536)
            if raw[12:14]!=b'\x08\x00': continue
            ip=raw[14:]; ihl=(ip[0]&15)*4
            if ip[9]!=17: continue
            body=ip[ihl:struct.unpack('!H',ip[2:4])[0]]
            if struct.unpack('!HH',body[:4])==(53,30000): answers[body[8:]]=ip[12:16]
            if len(answers)==2: break
        assert answers=={dns_a:DST,dns_b:alternate},answers
        print('concurrent DNS requests retain their original destination')
    finally:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        if upstream: upstream.close()
        host.close(); udp.close(); listen.close()
        directory.cleanup()
        if proc.returncode and proc.stderr: print(proc.stderr.read().decode(errors='replace'))

if __name__=='__main__': main()
