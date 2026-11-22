#!/usr/bin/env python3
"""Check an Apple Silicon candidate after copying it to a new directory."""
import os
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
APP=Path(os.environ.get('NETWORKSHARER_TEST_APP',ROOT/'build'/'standalone-candidate'/'局域网代理共享器.app'))
env=dict(os.environ,TMPDIR='/private/tmp')

def run(*args,**kwargs):
    return subprocess.run(list(map(str,args)),env=env,check=True,capture_output=True,text=True,**kwargs)

def within(path,base):
    try: path.resolve(strict=True).relative_to(base.resolve(strict=True)); return True
    except (FileNotFoundError,ValueError): return False

with tempfile.TemporaryDirectory(prefix='Network Sharer 搬移 ',dir='/private/tmp') as temporary:
    app=Path(temporary)/'另一位置'/'局域网代理共享器.app';app.parent.mkdir()
    run('/usr/bin/ditto',APP,app)
    run('/usr/bin/codesign','--verify','--deep','--strict',app)
    info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
    assert info['LSMinimumSystemVersion']=='14.0'
    executable=app/'Contents/MacOS'
    required=('HotspotLab','mobile_identity','session_supervisor','subnet_guard','lease_store',
              'socks_gateway','standalone_bridge','libslirp.0.dylib','libglib-2.0.0.dylib',
              'libiconv.2.dylib','libintl.8.dylib','libpcre2-8.0.dylib')
    for name in required: assert (executable/name).is_file(),name
    macho=[]
    for path in app.rglob('*'):
        if path.is_symlink():
            assert within(path,app),str(path)
        elif path.is_file():
            assert path.stat().st_nlink==1,str(path)
            with path.open('rb') as file: magic=file.read(4)
            if magic in (b'\xcf\xfa\xed\xfe',b'\xca\xfe\xba\xbe',b'\xbe\xba\xfe\xca'):
                macho.append(path)
    assert len(macho)>=len(required),len(macho)
    dependencies=[]
    for binary in macho:
        assert 'arm64' in run('/usr/bin/lipo','-archs',binary).stdout.split(),str(binary)
        build=run('/usr/bin/vtool','-show-build',binary).stdout
        minima=re.findall(r'\bminos\s+(\d+(?:\.\d+)*)',build)
        assert minima and all(tuple(map(int,v.split('.'))) <= (14,0) for v in minima),(str(binary),minima)
        lines=run('/usr/bin/otool','-arch','arm64','-L',binary).stdout.splitlines()[1:]
        ids=run('/usr/bin/otool','-arch','arm64','-D',binary).stdout.splitlines()[1:]
        own_id=ids[0].strip() if ids else ''
        for line in lines:
            dep=line.strip().split(' (compatibility version',1)[0]
            if dep==own_id: continue
            if dep.startswith('@rpath/'):
                resolved=app/'Contents/Frameworks'/dep[len('@rpath/'):]
                assert within(resolved,app),(str(binary),dep)
            elif dep.startswith('@loader_path/'):
                resolved=binary.parent/dep[len('@loader_path/'):]
                assert within(resolved,app),(str(binary),dep)
            elif dep.startswith('@executable_path/'):
                resolved=executable/dep[len('@executable_path/'):]
                assert within(resolved,app),(str(binary),dep)
            else:
                assert dep.startswith(('/System/Library/','/usr/lib/')),(str(binary),dep)
            dependencies.append(dep)
    print(f'Relocated bundle: {len(macho)} Mach-O files, {len(dependencies)} dependencies, '
          'symlinks, signatures, arm64 and macOS 14 targets verified')
