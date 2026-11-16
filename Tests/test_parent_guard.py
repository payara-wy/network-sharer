#!/usr/bin/env python3
"""Ensure helper processes exit if their controlling process is killed."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
launcher = r'''
import json,os,select,subprocess,sys,time,uuid
kind,root,target=sys.argv[1:]
env=os.environ.copy();env['NAPTD_CONTROLLER_PID']=str(os.getpid())
if kind in ('gateway','gateway_sandbox'):
 env['NAPTD_RELAY_TOKEN']=uuid.uuid4().hex
 command=[root+'/socks_gateway','direct','en0']; output='stdout'
 if kind=='gateway_sandbox': command=['/usr/bin/sandbox-exec','-p','(version 1) (allow default)']+command
elif kind=='dispatcher':
 env['NAPTD_DISPATCHER_PORT']='com.naptdlab.guard.'+uuid.uuid4().hex
 command=[root+'/mock_dispatcher']; output='stderr'
else:
 env['DYLD_INSERT_LIBRARIES']=root+'/private_runtime.dylib'
 command=[target]; output='stdout'
child=subprocess.Popen(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
pipe=getattr(child,output)
if not select.select([pipe],[],[],6)[0]: raise RuntimeError('child not ready')
line=pipe.readline()
if not any(s in line for s in ('gateway_ready','dispatcher_ready','target_ready')): raise RuntimeError('child failed: '+line)
print(json.dumps({'pid':child.pid}),flush=True)
while True: time.sleep(10)
'''

def alive(pid):
    result = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'stat='], capture_output=True, text=True)
    return result.returncode == 0 and result.stdout.strip() and not result.stdout.strip().startswith('Z')

with tempfile.TemporaryDirectory(prefix='hotspot-parent-guard-', dir='/private/tmp') as temp:
    temp = Path(temp)
    source, target = temp/'target.c', temp/'target'
    source.write_text('#include <stdio.h>\n#include <unistd.h>\nint main(void) { puts("target_ready"); fflush(stdout); for (;;) sleep(10); }\n')
    subprocess.run(['/usr/bin/clang', '-O2', str(source), '-o', str(target)], check=True)
    for kind in ('gateway', 'gateway_sandbox', 'dispatcher', 'shim'):
        parent = subprocess.Popen([sys.executable, '-c', launcher, kind, str(ROOT), str(target)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        child = None
        try:
            line = parent.stdout.readline()
            if not line:
                raise RuntimeError(kind+' parent failed: '+parent.stderr.read()[:300])
            child = json.loads(line)['pid']
            assert alive(child), kind+' was not alive before the parent stopped'
            parent.kill(); parent.wait(timeout=4)
            deadline = time.monotonic()+8
            while alive(child) and time.monotonic()<deadline: time.sleep(0.2)
            assert not alive(child), kind+' remained alive after its controller exited'
        finally:
            if parent.poll() is None: parent.kill(); parent.wait(timeout=3)
            if child and alive(child): os.kill(child, signal.SIGKILL)
print('Gateway, dispatcher and daemon shim stop after their controller disappears')
