#!/usr/bin/env python3
"""Test outbound interposition under a deny-direct sandbox, using a local proxy."""
import os
from pathlib import Path
import select
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
PROBE=Path(os.environ.get('NETWORKSHARER_TEST_SHIM_PROBE',ROOT/'shim_proxy_probe'))
SHIM=Path(os.environ.get('NETWORKSHARER_TEST_SHIM',ROOT/'private_runtime.dylib'))
GATEWAY=Path(os.environ.get('NETWORKSHARER_TEST_GATEWAY',ROOT/'socks_gateway'))
port=int(sys.argv[1]) if len(sys.argv)>1 else 1082
token=os.urandom(16).hex()
env=os.environ.copy(); env['NAPTD_RELAY_TOKEN']=token
gateway=subprocess.Popen([str(GATEWAY),'socks5',str(port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1,env=env)
try:
    ready,_,_=select.select([gateway.stdout],[],[],8)
    if not ready: raise RuntimeError('gateway did not start')
    line=gateway.stdout.readline().strip()
    if not line.startswith('gateway_ready:'): raise RuntimeError('gateway failed')
    _,tcp,dns=line.split(':')
    profile=f'''(version 1) (allow default) (deny network-outbound)
(allow network-bind) (allow network-inbound)
(allow network-outbound (remote ip "localhost:{tcp}"))
(allow network-outbound (remote ip "localhost:{dns}"))'''
    command=['/usr/bin/sandbox-exec','-p',profile,'/usr/bin/env',
             'DYLD_INSERT_LIBRARIES='+str(SHIM),
             'NAPTD_RELAY_TCP='+tcp,'NAPTD_RELAY_DNS='+dns,'NAPTD_RELAY_TOKEN='+token,
             str(PROBE)]
    result=subprocess.run(command,capture_output=True,text=True,timeout=30)
    print(result.stdout.strip()); print(result.stderr.strip(),file=sys.stderr)
    if result.returncode: raise SystemExit(result.returncode)
finally:
    gateway.terminate()
    try: gateway.wait(timeout=3)
    except subprocess.TimeoutExpired: gateway.kill(); gateway.wait(timeout=3)
