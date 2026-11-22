#!/usr/bin/env python3
"""Rebuild only the Swift UI in a fresh workspace-local copy of the working app.

No downloads, external headers, root, old-session cleanup or running-app writes.
"""
from pathlib import Path
import datetime
import hashlib
import os
import plistlib
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'build/standalone-candidate/局域网代理共享器.app'
SOURCES = ['HotspotLab.swift', 'LANProxySupport.swift', 'SharingView.swift']


def main():
    output = ROOT / 'build' / ('ui-candidate-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
    if not BASE.is_dir() or BASE.is_symlink():
        raise RuntimeError('Missing workspace-local base application')
    for path in BASE.rglob('*'):
        if path.is_symlink():
            raise RuntimeError('Base bundle contains a symbolic link: ' + str(path))
    if (ROOT / 'build').is_symlink() or not BASE.resolve().is_relative_to(ROOT):
        raise RuntimeError('Build path escaped the workspace')
    output.mkdir(exist_ok=False)
    cache = output / 'module-cache'; cache.mkdir()
    temporary = output / 'tmp'; temporary.mkdir()
    env = dict(os.environ, TMPDIR=str(temporary), CLANG_MODULE_CACHE_PATH=str(cache),
               MACOSX_DEPLOYMENT_TARGET='14.0')
    app = output / BASE.name
    shutil.copytree(BASE, app)
    executable = app / 'Contents/MacOS/HotspotLab'
    def run(*args):
        subprocess.run(list(map(str, args)), check=True, cwd=ROOT, env=env)
    run('/usr/bin/swiftc', '-target', 'arm64-apple-macosx14.0', '-parse-as-library', '-swift-version', '5', '-O',
        '-module-cache-path', cache, '-Xcc', '-fmodules-cache-path=' + str(cache),
        '-framework', 'SwiftUI', '-framework', 'AppKit', '-framework', 'SystemConfiguration',
        *(ROOT / 'Sources' / name for name in SOURCES), '-o', executable)
    # Keep the bundle identifier for credential continuity. This is a separate
    # candidate path so the current sharing process can run uninterrupted.
    info_path = app / 'Contents/Info.plist'
    info = plistlib.loads(info_path.read_bytes())
    assert info['CFBundleIdentifier'] == 'com.local.lansharer'
    info['CFBundleVersion'] = '2'
    info_path.write_bytes(plistlib.dumps(info, sort_keys=False))
    run('/usr/bin/codesign', '--force', '--sign', '-', executable)
    run('/usr/bin/codesign', '--force', '--sign', '-', app)
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', app)
    # The network engine in the copy must be byte-for-byte identical.
    for path in (BASE / 'Contents/MacOS').iterdir():
        if path.name == 'HotspotLab': continue
        assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256((app / 'Contents/MacOS' / path.name).read_bytes()).digest()
    for name in ('engine.sh', 'reconnect_helpers.sh'):
        assert (BASE / 'Contents/Resources' / name).read_bytes() == (app / 'Contents/Resources' / name).read_bytes()
    print('Candidate:', app, flush=True)
    return app


if __name__ == '__main__':
    main()
