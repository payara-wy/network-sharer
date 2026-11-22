#!/usr/bin/env python3
"""Exercise the LAN SOCKS5 listener without changing host network settings.

The listener binds only to the selected Wi-Fi address, so this test compiles a
copy of the gateway with the loopback address substituted for that interface.
It never listens on a real network address and never contacts the internet.
"""
import os
from pathlib import Path
import select
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'Sources/socks_gateway.c'
TOKEN=os.urandom(16).hex()
USER=b'phone'; PASSWORD=b'test-password'
ECHO=b'lan-proxy-echo'
ECHO_HOST='127.0.0.1'

def readn(sock,n):
    out=b''
    while len(out)<n:
        part=sock.recv(n-len(out))
        if not part: raise EOFError()
        out+=part
    return out

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                data=self.request.recv(4096)
                if not data: return
                self.request.sendall(data)
        except OSError:
            return

class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True

class Socks(socketserver.BaseRequestHandler):
    """Minimal upstream SOCKS5 proxy used to prove the phone path works."""
    def handle(self):
        sock=self.request; sock.settimeout(5)
        try:
            version,count=readn(sock,2); methods=readn(sock,count)
            if version!=5 or 0 not in methods: return
            sock.sendall(b'\x05\x00')
            header=readn(sock,4)
            if header[3]==1: address=socket.inet_ntoa(readn(sock,4))
            else: raise EOFError()
            port=struct.unpack('!H',readn(sock,2))[0]
            self.server.targets.append((address,port))
            upstream=socket.create_connection((address,port),timeout=5)
            sock.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01')
            sockets=[sock,upstream]
            try:
                while True:
                    ready,_,_=select.select(sockets,[],[],5)
                    if not ready: return
                    for item in ready:
                        data=item.recv(4096)
                        if not data: return
                        (upstream if item is sock else sock).sendall(data)
            finally:
                upstream.close()
        except (OSError,EOFError):
            return

class SocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
    def __init__(self):
        self.targets=[]
        super().__init__(('127.0.0.1',0),Socks)

def build(directory):
    source=SOURCE.read_text()
    # The LAN listener resolves its own Wi-Fi address through getifaddrs; for a
    # loopback-only test substitute a fixed address instead.
    old='''    struct ifaddrs *list=NULL; int found=0;
    if (!lan_interface[0] || getifaddrs(&list)) return 0;
    for (struct ifaddrs *p=list;p;p=p->ifa_next) {
        if (p->ifa_addr && p->ifa_addr->sa_family==AF_INET && !strcmp(p->ifa_name,lan_interface)) {
            *out=((struct sockaddr_in *)p->ifa_addr)->sin_addr; found=1; break;
        }
    }
    freeifaddrs(list);
    return found;'''
    new='''    (void)lan_interface; out->s_addr=htonl(INADDR_LOOPBACK); return 1;'''
    assert source.count(old)==1,'LAN address lookup changed; update the test'
    source=source.replace(old,new)
    # The loopback refusal is verified on a second copy; this one relaxes it so
    # the echo server on 127.0.0.1 can stand in for an internet host.
    guard="    uint32_t host=ntohl(address);\n    return host && (host>>24)!=127;"
    assert source.count(guard)==1,'LAN destination guard changed; update the test'
    strict=directory/'gateway-strict.c'
    strict.write_text(source)
    relaxed=directory/'gateway.c'
    # Only the loopback refusal is relaxed; 0.0.0.0 stays refused.
    relaxed_source=source.replace(guard,"    return address!=0;")
    # Egress is bound to the physical interface, which cannot reach a loopback
    # echo server; only in this copy is that binding skipped.
    bind="        if (setsockopt(fd,IPPROTO_IP,IP_BOUND_IF,&index,sizeof(index)) || bind(fd,(struct sockaddr *)&local,sizeof(local))) {"
    assert relaxed_source.count(bind)==1,'egress binding changed; update the test'
    relaxed_source=relaxed_source.replace(bind,"        if (0) {")
    relaxed.write_text(relaxed_source)
    binaries=[]
    for name,path in (('socks_gateway',relaxed),('socks_gateway_strict',strict)):
        binary=directory/name
        subprocess.run(['/usr/bin/clang','-O1','-g','-fsanitize=address,undefined','-Wall','-Wextra',
                        '-pthread','-I'+str(ROOT/'Sources'),str(path),'-o',str(binary)],check=True)
        binaries.append(binary)
    return binaries

def auth_file(directory,name,user,secret):
    path=directory/name
    path.write_bytes(bytes([len(user)])+user+bytes([len(secret)])+secret)
    path.chmod(0o600)
    return path

def start(binary,directory,mode,upstream,port,auth):
    env=os.environ.copy()
    env.update(NAPTD_RELAY_TOKEN=TOKEN,NAPTD_DNS_SERVER='203.0.113.53',NAPTD_LAN_INTERFACE='en0')
    if auth is not None: env['NAPTD_LAN_AUTH_FILE']=str(auth)
    if port is not None: env['NAPTD_LAN_PORT']=str(port)
    argument=upstream if mode=='direct' else str(upstream)
    return subprocess.Popen([str(binary),mode,str(argument)],env=env,
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)

def ready(proc):
    if not select.select([proc.stdout],[],[],10)[0]: raise RuntimeError('gateway did not start: '+proc.stderr.read()[:300])
    line=proc.stdout.readline().strip()
    if not line.startswith('gateway_ready:'): raise RuntimeError('gateway failed: '+line+' '+proc.stderr.read()[:300])
    return line

def handshake(port,user=USER,secret=PASSWORD,method=2):
    sock=socket.create_connection(('127.0.0.1',port),timeout=5)
    sock.settimeout(5)
    sock.sendall(bytes([5,1,method]))
    selection=readn(sock,2)
    if selection!=bytes([5,method]): raise AssertionError(('method',selection))
    if method==2:
        sock.sendall(bytes([1,len(user)])+user+bytes([len(secret)])+secret)
        assert readn(sock,2)==b'\x01\x00','credentials rejected'
    return sock

def connect_request(sock,address,port):
    sock.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(address)+struct.pack('!H',port))
    reply=readn(sock,10)
    assert reply[:2]==b'\x05\x00',reply
    return sock

def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0))
        return probe.getsockname()[1]

with tempfile.TemporaryDirectory(prefix='lanproxy-test-',dir=ROOT/'build') as temporary, \
     EchoServer(('127.0.0.1',0),Echo) as echo, SocksServer() as socks_server:
    directory=Path(temporary)
    binary,strict=build(directory)
    good=auth_file(directory,'lan-auth',USER,PASSWORD)
    threading.Thread(target=echo.serve_forever,daemon=True).start()
    threading.Thread(target=socks_server.serve_forever,daemon=True).start()
    echo_port=echo.server_address[1]; socks_port=socks_server.server_address[1]

    # 1) Direct mode: TCP reaches the echo server through the LAN listener.
    port=free_port()
    proc=start(binary,directory,'direct','en0',port,good)
    try:
        line=ready(proc)
        assert line.split(':')[3]==str(port),line
        with connect_request(handshake(port),ECHO_HOST,echo_port) as client:
            client.sendall(ECHO); assert readn(client,len(ECHO))==ECHO
        # Wrong password, missing method and a loopback destination are refused.
        with socket.create_connection(('127.0.0.1',port),timeout=5) as client:
            client.sendall(b'\x05\x01\x02'); assert readn(client,2)==b'\x05\x02'
            client.sendall(bytes([1,len(USER)])+USER+bytes([len(b'wrong')])+b'wrong')
            assert readn(client,2)[1]!=0,'wrong password accepted'
        with socket.create_connection(('127.0.0.1',port),timeout=5) as client:
            client.sendall(b'\x05\x01\x00'); assert readn(client,2)==b'\x05\xff'
        # The strict build refuses loopback destinations outright.
        strict_port=free_port()
        strict_proc=start(strict,directory,'direct','en0',strict_port,good)
        try:
            ready(strict_proc)
            with handshake(strict_port) as client:
                client.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',echo_port))
                assert readn(client,10)[1]!=0,'loopback destination accepted'
        finally:
            strict_proc.terminate(); strict_proc.wait(timeout=5)
        # Domain names go through the configured resolver, which is unreachable
        # here, so they fail closed instead of bypassing the resolver.
        with handshake(port) as client:
            client.sendall(b'\x05\x01\x00\x03\x0bexample.com'+struct.pack('!H',echo_port))
            assert readn(client,10)[1]!=0,'unresolvable name was accepted'
    finally:
        proc.terminate(); proc.wait(timeout=5)

    # 2) UDP ASSOCIATE: a datagram goes out through the Mac and the reply is
    #    framed with the destination address, as SOCKS5 requires.
    port=free_port()
    proc=start(binary,directory,'direct','en0',port,good)
    try:
        ready(proc)
        udp_server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        udp_server.bind(('127.0.0.1',0)); udp_server.settimeout(5)
        control=handshake(port)
        control.sendall(b'\x05\x03\x00\x01'+socket.inet_aton('0.0.0.0')+struct.pack('!H',0))
        reply=readn(control,10)
        assert reply[:2]==b'\x05\x00',reply
        relay=('127.0.0.1',struct.unpack('!H',reply[8:10])[0])
        datagram=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); datagram.settimeout(5)
        header=b'\x00\x00\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',udp_server.getsockname()[1])
        datagram.sendto(header+b'udp-payload',relay)
        payload,peer=udp_server.recvfrom(2048)
        assert payload==b'udp-payload',payload
        udp_server.sendto(b'udp-reply',peer)
        response,_=datagram.recvfrom(2048)
        assert response[:4]==b'\x00\x00\x00\x01' and response[10:]==b'udp-reply',response
        control.close(); datagram.close(); udp_server.close()
    finally:
        proc.terminate(); proc.wait(timeout=5)

    # 3) SOCKS5 upstream mode: the phone's traffic leaves through that proxy.
    port=free_port()
    proc=start(binary,directory,'socks5',socks_port,port,good)
    try:
        line=ready(proc)
        assert line.split(':')[3]==str(port),line
        with connect_request(handshake(port),ECHO_HOST,echo_port) as client:
            client.sendall(ECHO); assert readn(client,len(ECHO))==ECHO
        assert (ECHO_HOST,echo_port) in socks_server.targets,socks_server.targets
        # This mock upstream rejects UDP ASSOCIATE: do not fall back to direct.
        with handshake(port) as client:
            client.sendall(b'\x05\x03\x00\x01'+socket.inet_aton('0.0.0.0')+struct.pack('!H',0))
            assert readn(client,10)[1]==7,'Unsupported upstream must reject UDP without direct fallback'
    finally:
        proc.terminate(); proc.wait(timeout=5)

    # 4) Fail closed: missing credentials file, empty credentials or a bad port.
    unusable=[(None,free_port()),(auth_file(directory,'empty',b'',b''),free_port()),(good,'70000')]
    for name,lan_port in unusable:
        proc=start(binary,directory,'direct','en0',lan_port,name)
        try:
            assert proc.wait(timeout=7)!=0,'gateway accepted unusable LAN settings'
        finally:
            if proc.poll() is None: proc.terminate(); proc.wait(timeout=5)

    # 5) The LAN listener must never start without a port configured.
    proc=start(binary,directory,'direct','en0',None,good)
    try:
        line=ready(proc)
        assert len(line.split(':'))==3,line
    finally:
        proc.terminate(); proc.wait(timeout=5)
    socks_server.shutdown(); echo.shutdown()
print('LAN proxy: direct TCP and UDP, SOCKS5 upstream, mandatory credentials, loopback refusal and fail-closed startup passed')
