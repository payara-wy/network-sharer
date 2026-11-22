#!/usr/bin/env python3
"""Build the stability fix in a fresh copy of this branch's strict bundle.
No downloads, external dependencies, existing-bundle writes or session cleanup.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'build/standalone-strict/局域网代理共享器.app'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if not BASE.is_dir() or BASE.is_symlink() or (ROOT / 'build').is_symlink():
        raise RuntimeError('Missing or linked base bundle')
    if not BASE.resolve().is_relative_to(ROOT):
        raise RuntimeError('Base bundle escaped the workspace')
    before = {}
    for p in BASE.rglob('*'):
        if p.is_symlink(): raise RuntimeError('Unexpected symlink: ' + str(p))
        if p.is_file(): before[str(p.relative_to(BASE))] = digest(p)
    destination = ROOT / 'build' / ('stability-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
    destination.mkdir(exist_ok=False)
    temp = destination / 'tmp'; temp.mkdir()
    app = destination / BASE.name
    shutil.copytree(BASE, app)
    env = dict(os.environ, TMPDIR=str(temp), MACOSX_DEPLOYMENT_TARGET='14.0')
    def run(*args):
        subprocess.run(list(map(str, args)), check=True, cwd=ROOT, env=env)
    gateway = app / 'Contents/MacOS/socks_gateway'
    run('/usr/bin/clang', '-arch', 'arm64', '-mmacosx-version-min=14.0',
        '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
        ROOT / 'Sources/socks_gateway.c', '-o', gateway)
    # The DHCP core carries its own lease persistence; rebuild it with this source.
    libslirp = app / 'Contents/MacOS/libslirp.0.dylib'
    run('/usr/bin/clang', '-arch', 'arm64', '-mmacosx-version-min=14.0', '-O2', '-Wall', '-Wextra', '-Werror',
        '-I' + str(ROOT / 'ThirdParty/libslirp/src'),
        ROOT / 'Sources/standalone_bridge.c', ROOT / 'Sources/standalone_leases.c',
        libslirp, '-o', app / 'Contents/MacOS/standalone_bridge')
    cache = destination / 'swift-cache'; cache.mkdir()
    ui = app / 'Contents/MacOS/HotspotLab'
    run('/usr/bin/swiftc', '-target', 'arm64-apple-macosx14.0', '-parse-as-library', '-swift-version', '5', '-O',
        '-module-cache-path', cache, '-Xcc', '-fmodules-cache-path=' + str(cache),
        '-framework', 'SwiftUI', '-framework', 'AppKit', '-framework', 'SystemConfiguration',
        ROOT / 'Sources/HotspotLab.swift', ROOT / 'Sources/LANProxySupport.swift', ROOT / 'Sources/SharingView.swift',
        '-o', ui)
    info_path = app / 'Contents/Info.plist'
    info = plistlib.loads(info_path.read_bytes())
    assert info['CFBundleIdentifier'] == 'com.local.lansharer'
    info['CFBundleVersion'] = '5'
    info_path.write_bytes(plistlib.dumps(info, sort_keys=False))
    run('/usr/bin/codesign', '--force', '--sign', '-', gateway)
    run('/usr/bin/codesign', '--force', '--sign', '-', app / 'Contents/MacOS/standalone_bridge')
    run('/usr/bin/codesign', '--force', '--sign', '-', app)
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', app)
    after = {str(p.relative_to(BASE)): digest(p) for p in BASE.rglob('*') if p.is_file()}
    assert before == after, 'Base bundle changed during build'
    # This build also includes the user's requested one-line DNS UI correction.
    allowed = {'Contents/MacOS/socks_gateway', 'Contents/MacOS/standalone_bridge', 'Contents/MacOS/HotspotLab',
               'Contents/Info.plist', 'Contents/_CodeSignature/CodeResources'}
    for name, original in before.items():
        if name not in allowed: assert digest(app / name) == original, name
    (destination / 'build-manifest.json').write_text(json.dumps({
        'base': str(BASE), 'base_unchanged': True, 'app': str(app),
        'changed_bundle_files': sorted(allowed),
        'sources': {name: digest(ROOT / 'Sources' / name) for name in
                    ['socks_gateway.c', 'lan_udp.h', 'lan_dns.h', 'upstream_udp.h', 'parent_guard.h',
                     'HotspotLab.swift', 'LANProxySupport.swift', 'SharingView.swift']}
    }, indent=2))
    print('Candidate:', app, flush=True)
    return app


if __name__ == '__main__': main()
