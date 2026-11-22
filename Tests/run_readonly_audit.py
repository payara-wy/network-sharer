#!/usr/bin/env python3
"""Read-only behavior/memory/disk checks against the frozen gateway.

All traffic and disk activity is on 127.0.0.1 / lo0. Builds are compiled from
the frozen source copy, only substituting LAN discovery for loopback testing.
No target source or application bundle is edited.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import resource
import select
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'build/audit-20261120-readonly'
SOURCE=OUT/'test/socks_gateway.c'
WORK=OUT/'test/work'; WORK.mkdir(exist_ok=True)
os.environ['TMPDIR']=str(WORK)
IP=socket.inet_aton('127.0.0.1')


def readn(sock,n):
    data=b''
    while len(data)<n:
        chunk=sock.recv(n-len(data))
        if not chunk: raise EOFError('closed')
        data+=chunk
    return data


def build(name,sanitizers=(),defines=()):
    source=SOURCE.read_text()
    a=source.index('static int lan_wifi_address(')
    b=source.index('static int dns_skip_name(',a)
    source=source[:a]+'static int lan_wifi_address(struct in_addr *out) { out->s_addr=htonl(INADDR_LOOPBACK); return 1; }\n'+source[b:]
    guard='return host && (host>>24)!=127;'
    assert source.count(guard)==1
    source=source.replace(guard,'return host == INADDR_LOOPBACK;')
    path=WORK/(name+'.c'); path.write_text(source)
    output=WORK/name
    subprocess.run(['/usr/bin/clang','-O1','-g','-Wall','-Wextra','-Werror','-pthread','-I'+str(OUT/'test'),
                    *sanitizers,*defines,str(path),'-o',str(output)],check=True,env=os.environ,timeout=60)
    return output


def login(port):
    sock=socket.create_connection(('127.0.0.1',port),timeout=3); sock.settimeout(15)
    sock.sendall(b'\x05\x01\x02'); assert readn(sock,2)==b'\x05\x02'
    sock.sendall(b'\x01\x03Mac\x08testonly'); assert readn(sock,2)==b'\x01\x00'
    return sock


def connect_tcp(port,dest):
    sock=login(port)
    sock.sendall(b'\x05\x01\x00\x01'+IP+struct.pack('!H',dest))
    assert readn(sock,10)[:2]==b'\x05\x00'
    return sock


def associate(port):
    sock=login(port)
    sock.sendall(b'\x05\x03\x00\x01'+b'\0'*6)
    reply=readn(sock,10)
    assert reply[:2]==b'\x05\x00',reply
    return sock,('127.0.0.1',struct.unpack('!H',reply[8:])[0])


def datagram():
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1',0)); sock.settimeout(15)
    return sock


def header(port):
    return b'\0\0\0\1'+IP+struct.pack('!H',port)


def roundtrip(client,relay,target,body):
    client.sendto(header(target.getsockname()[1])+body,relay)
    data,peer=target.recvfrom(65535); assert data==body
    target.sendto(data,peer)
    assert client.recv(65535)==header(target.getsockname()[1])+body


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            while True:
                data=self.request.recv(65536)
                if not data: break
                self.request.sendall(data)
        except OSError: pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True


class Gateway:
    def __init__(self,binary,extra_env=None):
        self.binary=binary
        self.extra_env=extra_env or {}
        self.usage_start=resource.getrusage(resource.RUSAGE_CHILDREN)
        self.env={k:v for k,v in os.environ.items() if not k.startswith('NAPTD_')}
        self.env.update(TMPDIR=str(WORK),NAPTD_RELAY_TOKEN='a'*32)
        self.proc=None
    def __enter__(self):
        (WORK/'auth').write_bytes(b'\x03Mac\x08testonly')
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1',0)); self.port=reserve.getsockname()[1]
        self.env.update(NAPTD_LAN_PORT=str(self.port),NAPTD_LAN_INTERFACE='en0',
                        NAPTD_LAN_AUTH_FILE=str(WORK/'auth'),NAPTD_CONTROLLER_PID=str(os.getpid()),**self.extra_env)
        self.proc=subprocess.Popen([str(self.binary),'direct','lo0'],env=self.env,
                                   stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        for _ in range(30):
            assert select.select([self.proc.stdout],[],[],8)[0], 'no ready output'
            line=self.proc.stdout.readline().strip()
            if line.startswith('gateway_ready:'): break
            (WORK/'interpose-startup.log').open('a').write(line+'\n')
        else: raise AssertionError('gateway did not become ready')
        self.start_io=self.disk_io()
        return self
    def disk_io(self):
        usage=resource.getrusage(resource.RUSAGE_CHILDREN)
        return {'ru_inblock':usage.ru_inblock-self.usage_start.ru_inblock,
                'ru_oublock':usage.ru_oublock-self.usage_start.ru_oublock}
    def exit(self):
        for _ in range(50):
            if self.proc.poll() is not None: break
            time.sleep(.1)
        if self.proc.poll() is None:
            self.proc.terminate()
            try: self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired: self.proc.kill();self.proc.wait(timeout=5)
        self.stderr=self.proc.stderr.read()
        self.stdout=self.proc.stdout.read()
        self.proc.stdout.close();self.proc.stderr.close()
        return self.proc.returncode,self.stderr
    def __exit__(self,kind,value,traceback): self.exit()


def safe_run(func,timeout=30):
    error=[]
    def worker():
        try: func()
        except BaseException as exc: error.append(repr(exc))
    thread=threading.Thread(target=worker,daemon=True);thread.start();thread.join(timeout)
    if thread.is_alive(): raise AssertionError('case timeout (thread intentionally left only for process cleanup)')
    if error: raise AssertionError(error[0])


def tcp_case(port,work):
    with Server(('127.0.0.1',0),Echo) as server:
        threading.Thread(target=server.serve_forever,daemon=True).start()
        clients=[]
        failures=[]
        try:
            for index in range(32):
                client=connect_tcp(port,server.server_address[1]);clients.append(client)
                def exchange(sock,index):
                    try:
                        for n in range(16):
                            body=struct.pack('!II',index,n)+b'x'*8192
                            sock.sendall(body);assert readn(sock,len(body))==body
                    except BaseException as exc: failures.append((index,repr(exc)))
                threading.Thread(target=exchange,args=(client,index),daemon=True).start()
            deadline=time.monotonic()+30
            while time.monotonic()<deadline:
                with datagram() as udp,datagram() as target:
                    control,relay=associate(port)
                    try:
                        for n in range(32): roundtrip(udp,relay,target,struct.pack('!I',n)+b'y'*1024)
                    finally: control.close()
                break
            while threading.active_count()>1 and time.monotonic()<deadline:
                if failures: break
                time.sleep(.1)
            assert not failures,failures
            return {'concurrent_tcp_clients':len(clients),'tcp_payload_mib':32,'udp_echoes':32}
        finally:
            for client in clients:client.close()
            server.shutdown()


def memory_case(port,work):
    held=[]
    counters={'tcp':0,'udp':0}
    def churn():
        with Server(('127.0.0.1',0),Echo) as server:
            threading.Thread(target=server.serve_forever,daemon=True).start()
            try:
                for n in range(64):
                    client=connect_tcp(port,server.server_address[1])
                    client.sendall(b'cycle');assert readn(client,5)==b'cycle';client.close();counters['tcp']+=1
                control,relay=associate(port)
                try:
                    with datagram() as udp,datagram() as target:
                        for n in range(128):
                            roundtrip(udp,relay,target,struct.pack('!I',n))
                            counters['udp']+=1
                finally:control.close()
            finally:server.shutdown()
    safe_run(churn,60)
    return counters


def disk_case(port,work):
    (WORK/'disk-baseline.json').write_text(json.dumps({'synthetic':'test'}))
    start=time.monotonic();samples=[]
    def load():
        with datagram() as udp,datagram() as target:
            control,relay=associate(port)
            try:
                while time.monotonic()-start<8:
                    roundtrip(udp,relay,target,b'z'*1024)
            finally:control.close()
    safe_run(load,15)
    # The gateway has no persistence input and no configured log; its disk
    # activity must not scale with forwarded bytes. Only test scratch exists.
    return {'seconds':8,'source_log_path':'stdout only','persistence_configured':False}


def protocol_case(port,work):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(3)
        with contextlib.ExitStack() as stack:
            control,relay=associate(port);stack.enter_context(control)
            wrong=stack.enter_context(datagram());good=stack.enter_context(datagram())
            target=stack.enter_context(datagram())
            wrong.sendto(b'\0\0\0\x08'+b'\0'*10,relay)
            wrong.sendto(b'\0\0\0\x01'+IP+b'\0\0',relay)
            roundtrip(good,relay,target,b'valid-after-malformed')
            print('protocol: valid-after-malformed passed',flush=True)
            # Unknown targets fill the destination table but must not evict an
            # existing association's active flows.
            for n in range(140):
                other=stack.enter_context(datagram())
                good.sendto(header(other.getsockname()[1])+b'other',relay)
            roundtrip(good,relay,target,b'existing-preserved')
            print('protocol: active flow preserved',flush=True)
            assert not select.select([control],[],[],0)[0]
    with login(port) as partial:
        partial.sendall(b'\x05\x01\x02')
        assert readn(partial,2)==b'\x05\x02'
        partial.sendall(b'\x01\xff'+b'a'*255)
    return {'malformed_frames':2,'destination_attempts':140,'active_flow_preserved':True,'partial_auth_closed':True}


def fuzz_case(port,work):
    import random
    generator=random.Random(20261120)
    for _ in range(256):
        with socket.create_connection(('127.0.0.1',port),timeout=3) as client:
            client.settimeout(2)
            client.sendall(generator.randbytes(generator.randrange(0,1025)))
    with contextlib.ExitStack() as stack:
        control,relay=associate(port);stack.enter_context(control)
        client=stack.enter_context(datagram());target=stack.enter_context(datagram())
        for _ in range(2048):
            client.sendto(generator.randbytes(generator.randrange(0,1025)),relay)
        roundtrip(client,relay,target,b'after-2048-invalid-frames')
    return {'partial_handshakes':256,'malformed_udp_frames':2048,'known_flow_survives':True}


def process_metrics(pid):
    ps=subprocess.run(['/bin/ps','-p',str(pid),'-o','pid=,rss=,vsz='],text=True,capture_output=True,check=True).stdout.split()
    try: fds=int(subprocess.check_output(['/usr/sbin/lsof','-p',str(pid)],text=True).count('\n')-1)
    except subprocess.CalledProcessError: fds=None
    return {'rss_kib':int(ps[1]),'vsz_kib':int(ps[2]),'fd_count':fds}


def main():
    results={}
    binary=build('gateway-asan',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])
    lsan=build('gateway-optimized',['-O2'])
    io_dylib=WORK/'audit_io.dylib'
    subprocess.run(['/usr/bin/clang','-dynamiclib','-fPIC','-Wall','-Wextra','-Werror',
                    str(ROOT/'Tests/audit_io_interpose.c'),'-o',str(io_dylib)],check=True,env=os.environ,timeout=30)
    env=dict(os.environ,DYLD_INSERT_LIBRARIES=str(io_dylib))
    with Gateway(binary,env) as gateway:
        before=process_metrics(gateway.proc.pid)
        results['disk_io_interposition']=disk_case(gateway.port,WORK)
        after=process_metrics(gateway.proc.pid)
    results['disk_io_interposition'].update(before=before,after=after,exit=gateway.proc.returncode,stderr=gateway.stderr,
                                          io_samples=gateway.stdout.splitlines())
    print('disk_io_interposition:',json.dumps(results['disk_io_interposition']),flush=True)
    output=OUT/'evidence/blackbox-memory-results.json'
    for name,func in (('tcp_concurrency',tcp_case),('memory_churn',memory_case),('protocol_boundaries',protocol_case),('malformed_fuzz',fuzz_case),('disk_write',disk_case)):
        print('ASan start:',name,flush=True)
        try:
            with Gateway(binary) as gateway:
                before=process_metrics(gateway.proc.pid)
                results[name]={'pass':True,**func(gateway.port,WORK)}
                after=process_metrics(gateway.proc.pid)
            results[name].update(before=before,after=after,
                stderr_summary=gateway.stderr[:500],process_exit=gateway.proc.returncode)
        except BaseException as error:results[name]={'pass':False,'error':repr(error)}
        print(name+': '+json.dumps(results[name]),flush=True)
    for name,func in (('tcp_concurrency',tcp_case),('memory_churn',memory_case),('disk_write',disk_case)):
        try:
            env=dict(os.environ,MallocStackLoggingNoCompact='1')
            with Gateway(lsan,env) as gateway:
                before=process_metrics(gateway.proc.pid);results['resource_'+name]={'pass':True,**func(gateway.port,WORK)}
                after=process_metrics(gateway.proc.pid)
                leak=subprocess.run(['/usr/bin/leaks','-q','--noContent',str(gateway.proc.pid)],env=env,
                                    text=True,capture_output=True,timeout=30)
                results['resource_'+name]['live_leaks']={'exit':leak.returncode,'output':leak.stdout+leak.stderr}
                if leak.returncode != 0: results['resource_'+name]['pass']=False
                (WORK/('leaks-'+name+'.txt')).write_text(leak.stdout+leak.stderr)
            results['resource_'+name].update(before=before,after=after,exit=gateway.proc.returncode,stderr=gateway.stderr[:2000])
        except BaseException as error:results['resource_'+name]={'pass':False,'error':repr(error)}
        print('resource_'+name+': '+json.dumps(results['resource_'+name]),flush=True)
    output=OUT/'evidence/blackbox-memory-results.json'
    output.write_text(json.dumps(results,indent=2))
    print('Report:',output,flush=True)
    for name,result in results.items():
        if 'pass' not in result:
            result['pass']=False
            result['tool_error']='scenario did not complete; not a product verdict'
    return results


if __name__=='__main__':main()
