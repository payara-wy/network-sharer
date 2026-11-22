#!/usr/bin/env python3
"""Build the isolated packet-test prototype against locally prepared GLib."""
from pathlib import Path
import os
import re
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'ThirdParty/libslirp'
OUTPUT=Path(os.environ.get('NETWORKSHARER_PROTO_OUTPUT',str(ROOT/'build/standalone-prototype')))
PREFIX=Path(os.environ.get('NETWORKSHARER_GLIB_PREFIX','/private/tmp/networksharer-deps/unpacked/glib/2.90.1'))
RUNTIME=Path(os.environ.get('NETWORKSHARER_PROTO_RUNTIME','/private/tmp/networksharer-deps/runtime'))
SANITIZERS=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if os.environ.get('NETWORKSHARER_SANITIZE')=='1' else []

OUTPUT.mkdir(parents=True,exist_ok=True)
for item in RUNTIME.glob('*.dylib'):
    shutil.copy2(item,OUTPUT/item.name)
meson=(SOURCE/'meson.build').read_text()
files=re.findall(r"'((?:src/)[^']+\.c)'",meson.split('sources = [',1)[1].split(']',1)[0])
assert len(files)==31
cmd=['/usr/bin/clang','-dynamiclib','-arch','arm64','-O2','-g','-mmacosx-version-min=14.0']+SANITIZERS+[
     '-DBUILDING_LIBSLIRP','-DG_LOG_DOMAIN="Slirp"','-I'+str(SOURCE/'src'),
     '-I'+str(PREFIX/'include/glib-2.0'),'-I'+str(PREFIX/'lib/glib-2.0/include'),
     '-install_name','@loader_path/libslirp.0.dylib']
cmd += [str(SOURCE/name) for name in files]
cmd += [str(RUNTIME/'libglib-2.0.0.dylib'),'-lresolv','-o',str(OUTPUT/'libslirp.0.dylib')]
subprocess.run(cmd,check=True)
subprocess.run(['/usr/bin/clang','-arch','arm64','-O2','-Wall','-Wextra']+SANITIZERS+['-I'+str(SOURCE/'src'),
                str(ROOT/'Sources/standalone_bridge.c'),str(ROOT/'Sources/standalone_leases.c'),str(OUTPUT/'libslirp.0.dylib'),
                '-o',str(OUTPUT/'standalone_bridge')],check=True)
print('Built isolated prototype')
