#!/usr/bin/env python3
"""Scan an isolated dispatcher after repeated requests; never inspect contents."""
import os
from pathlib import Path
import re
import select
import subprocess
import tempfile
import uuid

ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='networksharer-dispatcher-',dir='/private/tmp') as tmp:
    probe=Path(tmp)/'client'
    subprocess.run(['/usr/bin/clang','-O2','-framework','CoreFoundation',str(ROOT/'Tests/dispatcher_stress.c'),'-o',str(probe)],check=True)
    name='com.local.networksharer.stress.'+uuid.uuid4().hex
    stub=subprocess.Popen([str(ROOT/'mock_dispatcher')],env=dict(os.environ,NAPTD_DISPATCHER_PORT=name),
                          stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
    try:
        assert select.select([stub.stderr],[],[],5)[0] and 'dispatcher_ready' in stub.stderr.readline()
        subprocess.run([str(probe),name],check=True,timeout=30)
        result=subprocess.run(['/usr/bin/leaks','-q','--noContent','--nostacks',str(stub.pid)],capture_output=True,text=True,timeout=30)
        summary=[line.strip() for line in result.stdout.splitlines() if re.search(r'\b[0-9]+ leaks? for\b',line)]
        print('leak_scan_exit='+str(result.returncode)+' '+(' '.join(summary) or 'no summary'))
        assert result.returncode==0
    finally:
        stub.terminate(); stub.wait(timeout=5)
