#!/usr/bin/env python3
"""Actual idle-TCP black-box test, not a source-level claim or shortened timer."""
import argparse
import importlib.util
import json
from pathlib import Path
import select
import socket
import socketserver
import struct
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('readonly_audit',ROOT/'Tests/run_readonly_audit.py')
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)

class IdleEcho(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(600)
        try:
            while True:
                data=self.request.recv(65536)
                if not data: return
                self.request.sendall(data)
        except OSError: return

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--seconds',type=int,default=315)
    args=parser.parse_args()
    work=audit.OUT/'test/work'
    with audit.Server(('127.0.0.1',0),IdleEcho) as server:
        threading.Thread(target=server.serve_forever,daemon=True).start()
        with audit.Gateway(work/'gateway-asan') as gateway:
            sock=audit.connect_tcp(gateway.port,server.server_address[1])
            sock.sendall(b'before-idle');assert audit.readn(sock,11)==b'before-idle'
            report={'seconds_waited':args.seconds,'close_after_300_seconds':False}
            start=time.monotonic()
            elapsed=0
            while elapsed<args.seconds:
                remaining=args.seconds-elapsed
                readable,_,_=select.select([sock],[],[],min(remaining,2))
                if readable:
                    report['close_after_300_seconds']=True
                    report['elapsed_seconds']=round(time.monotonic()-start,3)
                    report['received']=sock.recv(1024).decode('ascii',errors='replace')
                    break
                elapsed=time.monotonic()-start
            if not report['close_after_300_seconds']:
                sock.sendall(b'after-idle')
                assert audit.readn(sock,10)==b'after-idle'
            sock.close();server.shutdown()
    output=audit.OUT/'evidence/idle-tcp-result.json';output.write_text(json.dumps(report,indent=2))
    print(json.dumps(report),flush=True)
    return 0 if report['close_after_300_seconds'] else 1

if __name__=='__main__':raise SystemExit(main())
