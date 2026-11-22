#!/usr/bin/env python3
"""Repack the stability candidate with the rebuilt libslirp only.

Copies the existing candidate, replaces Contents/MacOS/libslirp.0.dylib with the
freshly rebuilt library, bumps CFBundleVersion, re-signs ad hoc, verifies the
source candidate was not mutated, and writes a build manifest. No downloads,
no existing-bundle writes, no session cleanup, no external dependencies.
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
BASE = ROOT / 'build/stability-20261121-002712/局域网代理共享器.app'
NEWLIB = ROOT / 'build/rebuild-glib-20261121/libslirp.0.dylib'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if not BASE.is_dir() or BASE.is_symlink() or (ROOT / 'build').is_symlink():
        raise RuntimeError('Missing or linked base bundle')
    if not NEWLIB.is_file() or not NEWLIB.resolve().is_relative_to(ROOT):
        raise RuntimeError('Rebuilt library missing or escaped workspace')
    before = {str(p.relative_to(BASE)): digest(p) for p in BASE.rglob('*') if p.is_file()}
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    destination = ROOT / 'build' / ('repack-' + stamp)
    destination.mkdir(exist_ok=False)
    temp = destination / 'tmp'; temp.mkdir()
    app = destination / BASE.name
    shutil.copytree(BASE, app)
    target = app / 'Contents/MacOS/libslirp.0.dylib'
    shutil.copy2(NEWLIB, target)
    os.chmod(target, 0o755)
    info_path = app / 'Contents/Info.plist'
    info = plistlib.loads(info_path.read_bytes())
    assert info['CFBundleIdentifier'] == 'com.local.lansharer'
    old_version = int(info.get('CFBundleVersion', '1'))
    info['CFBundleVersion'] = str(old_version + 1)
    info_path.write_bytes(plistlib.dumps(info, sort_keys=False))
    for item in (target, app):
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(item)], check=True)
    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)], check=True)
    after = {str(p.relative_to(BASE)): digest(p) for p in BASE.rglob('*') if p.is_file()}
    assert before == after, 'Source candidate changed during repack'
    changed = {'Contents/MacOS/libslirp.0.dylib': {'old': before['Contents/MacOS/libslirp.0.dylib'],
                                                     'new': digest(target)},
               'Contents/Info.plist': info['CFBundleVersion']}
    (destination / 'build-manifest.json').write_text(json.dumps({
        'base': str(BASE), 'base_unchanged': True, 'app': str(app),
        'rebuilt_library': str(NEWLIB),
        'library': {'from_sha256': before['Contents/MacOS/libslirp.0.dylib'], 'to_sha256': digest(target)},
        'cf_bundle_version': info['CFBundleVersion'], 'changed': changed,
    }, indent=2))
    print('Candidate:', app, flush=True)
    print('libslirp', before['Contents/MacOS/libslirp.0.dylib'], '->', digest(target), flush=True)
    return app


if __name__ == '__main__':
    main()