#!/usr/bin/env python3
"""Snapshot changes are atomic; unchanged host identities do not touch disk."""
import os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
src=(ROOT/'Sources/engine.sh').read_text()
function=src.split('refresh_host_macs() {',1)[1].split('\nif [ "$portcount" -gt 0 ]; then',1)[0]
with tempfile.TemporaryDirectory(prefix='networksharer-mac-refresh-',dir='/private/tmp') as tmp:
    root=Path(tmp); data=root/'ifconfig-output'; fake=root/'ifconfig'; target=root/'host-macs'
    fake.write_text('#!/bin/sh\ncat "$FAKE_IFCONFIG"\n');fake.chmod(0o700)
    func='refresh_host_macs() {'+function.replace('/sbin/ifconfig -a',str(fake)+' -a')
    env=dict(os.environ,FAKE_IFCONFIG=str(data),TEST_DIR=tmp)
    script='set -u\ndir="$TEST_DIR"\n'+func+'\nrefresh_host_macs\n'
    def run(success=True):
        p=subprocess.run(['/bin/bash','-c',script],env=env,capture_output=True,text=True)
        assert (p.returncode==0)==success,(p.returncode,p.stderr)
    data.write_text('en0: flags=0\n\tether aa:bb:cc:dd:ee:ff\nen7: flags=0\n\tether 12:34:56:78:90:ab\n')
    run(); assert target.read_text()=='12:34:56:78:90:ab\naa:bb:cc:dd:ee:ff\n'
    initial=target.stat(); run(); current=target.stat()
    assert (initial.st_ino,initial.st_mtime_ns)==(current.st_ino,current.st_mtime_ns), 'unchanged list rewrote disk'
    data.write_text('en0: flags=0\n\tether aa:bb:cc:dd:ee:ff\nen8: flags=0\n\tether 12:34:56:78:90:ac\n')
    run(); assert '12:34:56:78:90:ac\n' in target.read_text() and target.stat().st_ino!=initial.st_ino
    original=target.read_text(); data.write_text('en0: flags=0\n\tether broken\n'); run(False)
    assert target.read_text()==original
    data.write_text('en0: flags=0\n\tether 02:00:00:00:00:00\n'); run(False)
    assert target.read_text()==original
    assert target.stat().st_mode&0o077==0
print('Host MAC snapshots update atomically only on real changes')
