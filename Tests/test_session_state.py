#!/usr/bin/env python3
"""Exercise app session discovery with live, dead and stale state records."""
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'Sources/HotspotLab.swift').read_text()
helper=source[source.index('func sessionPossiblyActive('):source.index('func observedClients(')]
driver='''import Foundation
import Darwin
'''+helper+'''
let file=CommandLine.arguments[1]
try! "state".write(toFile:file,atomically:true,encoding:.utf8)
assert(sessionPossiblyActive(["state":"running","daemon_pid":String(getpid())],statePath:file))
assert(!sessionPossiblyActive(["state":"running","daemon_pid":"2147483647"],statePath:file))
assert(sessionPossiblyActive(["state":"starting"],statePath:file))
try! FileManager.default.setAttributes([.modificationDate:Date(timeIntervalSinceNow:-100)],ofItemAtPath:file)
assert(!sessionPossiblyActive(["state":"starting"],statePath:file))
assert(!sessionPossiblyActive(["state":"stopped"],statePath:file))
print("Live, missing, old starting and stopped session records were classified correctly")
'''
with tempfile.TemporaryDirectory(prefix='networksharer-state-test-',dir='/private/tmp') as tmp:
    source_path=Path(tmp)/'probe.swift'; binary=Path(tmp)/'probe'
    source_path.write_text(driver)
    subprocess.run(['/usr/bin/swiftc','-swift-version','5','-module-cache-path','/private/tmp/hotspot-swift-cache',
                    '-Xcc','-fmodules-cache-path=/private/tmp/hotspot-swift-cache',str(source_path),'-o',str(binary)],check=True)
    subprocess.run([str(binary),str(Path(tmp)/'state')],check=True)
