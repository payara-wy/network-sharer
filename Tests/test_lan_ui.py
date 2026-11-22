#!/usr/bin/env python3
"""Build and run deterministic UI/state tests entirely within this workspace."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
work = Path(tempfile.mkdtemp(prefix='ui-validation-', dir=ROOT / 'build'))
cache = work / 'cache'; cache.mkdir()
tmp = work / 'tmp'; tmp.mkdir()
env = dict(os.environ, TMPDIR=str(tmp), CLANG_MODULE_CACHE_PATH=str(cache))
source = (ROOT / 'Sources/HotspotLab.swift').read_text()
assert source.count('@main struct HotspotLabApp: App') == 1
(work / 'Model.swift').write_text(source.split('@main struct HotspotLabApp: App', 1)[0])
binary = work / 'ui-tests'
subprocess.run(['/usr/bin/swiftc', '-parse-as-library', '-swift-version', '5', '-target', 'arm64-apple-macosx14.0',
                '-module-cache-path', str(cache), '-Xcc', '-fmodules-cache-path=' + str(cache),
                '-framework', 'SwiftUI', '-framework', 'AppKit', '-framework', 'SystemConfiguration',
                str(work / 'Model.swift'), str(ROOT / 'Sources/LANProxySupport.swift'),
                str(ROOT / 'Sources/SharingView.swift'), str(ROOT / 'Tests/LANProxyUITests.swift'), '-o', str(binary)],
               check=True, cwd=ROOT, env=env, timeout=600)
# Host the test executable in a disposable real bundle so component checks
# remain meaningful in screenshots. Never launch its sharing engine.
app = work / 'UIValidation.app'
shutil.copytree(ROOT / 'build/standalone-udp-final/局域网代理共享器.app', app)
shutil.copy2(binary, app / 'Contents/MacOS/HotspotLab')
subprocess.run([str(app / 'Contents/MacOS/HotspotLab'), 'preferences-test', str(work)],
               check=True, cwd=ROOT, env=env, timeout=60)
print('Validation directory:', work, flush=True)
