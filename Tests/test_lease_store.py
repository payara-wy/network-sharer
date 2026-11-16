#!/usr/bin/env python3
"""Check lease-store ownership and link defenses without administrator access."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='networksharer-lease-store-',dir='/private/tmp') as temporary:
    root=Path(temporary); parent=root/'parent'; parent.mkdir(mode=0o700); binary=root/'lease_store'
    subprocess.run(['/usr/bin/clang','-O1','-g','-fsanitize=address,undefined','-Wall','-Wextra',
                    '-DNETWORKSHARER_LEASE_PARENT="'+str(parent)+'"',
                    '-DNETWORKSHARER_EXPECTED_UID='+str(os.geteuid()),
                    str(ROOT/'Sources/lease_store.c'),'-o',str(binary)],check=True)
    def invoke(): return subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
    directory=parent/'com.local.networksharer'; lease=directory/'dhcp-leases.ini'
    first=invoke()
    assert first.returncode==0 and first.stdout.strip()==str(lease),(first.returncode,first.stderr)
    assert directory.stat().st_mode&0o777==0o700 and lease.stat().st_mode&0o777==0o600
    lease.write_text('synthetic state')
    assert invoke().returncode==0 and lease.read_text()=='synthetic state'

    sentinel=root/'sentinel'; sentinel.write_text('do not change')
    lease.unlink(); lease.symlink_to(sentinel)
    assert invoke().returncode!=0 and sentinel.read_text()=='do not change'
    lease.unlink(); os.link(sentinel,lease)
    assert invoke().returncode!=0 and sentinel.read_text()=='do not change'
    lease.unlink(); shutil.rmtree(directory); directory.symlink_to(root,target_is_directory=True)
    assert invoke().returncode!=0
    directory.unlink(); directory.mkdir(mode=0o700); directory.chmod(0o777)
    assert invoke().returncode!=0
    directory.chmod(0o700); parent.chmod(0o777)
    assert invoke().returncode!=0
print('Lease store: persistence, restrictive permissions, symlinks and hard links checked')
