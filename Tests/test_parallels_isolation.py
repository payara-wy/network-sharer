#!/usr/bin/env python3
"""Use a private fake config and dispatcher; do not modify Parallels."""
import os
from pathlib import Path
import select
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
DISPATCHER = Path(os.environ.get('NETWORKSHARER_TEST_DISPATCHER', ROOT/'mock_dispatcher'))
SHIM = Path(os.environ.get('NETWORKSHARER_TEST_SHIM', ROOT/'private_runtime.dylib'))
with tempfile.TemporaryDirectory(prefix='networksharer-isolation-', dir='/private/tmp') as tmp:
    directory = Path(tmp)
    (directory/'network.desktop.xml').write_text('isolated-config')
    probe = directory/'probe'
    subprocess.run(['/usr/bin/clang', '-O2', '-framework', 'CoreFoundation',
                    str(ROOT/'Tests/isolation_probe.c'), '-o', str(probe)], check=True)
    port = 'com.local.networksharer.isolation.'+uuid.uuid4().hex
    env = dict(os.environ, NAPTD_DISPATCHER_PORT=port)
    stub = subprocess.Popen([str(DISPATCHER)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([stub.stderr], [], [], 5)[0] and 'dispatcher_ready' in stub.stderr.readline()
        profile = '''(version 1) (allow default) (deny file-write*)
(allow file-write* (literal "/dev/null"))
(deny file-read* (subpath "/Library/Preferences/Parallels"))
(deny file-read* (literal "/Library/Logs/parallels.log"))'''
        result = subprocess.run(['/usr/bin/sandbox-exec', '-p', profile, '/usr/bin/env',
                                 'NAPTD_CONFIG_DIR='+str(directory), 'DYLD_INSERT_LIBRARIES='+str(SHIM), str(probe)], env=env,
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, (result.returncode, result.stderr)
        print(result.stdout.strip())
    finally:
        stub.terminate(); stub.wait(timeout=5)
