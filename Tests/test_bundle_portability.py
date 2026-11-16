#!/usr/bin/env python3
"""Verify the bundle after relocation, without assuming Parallels is running."""
import os
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
APP=Path(os.environ.get('NETWORKSHARER_TEST_APP',ROOT/'build'/'网络共享器正式版'/'网络共享器.app'))
env=dict(os.environ,TMPDIR='/private/tmp')

def run(*args, **kwargs):
    return subprocess.run(list(map(str,args)),env=env,check=True,capture_output=True,text=True,**kwargs)

with tempfile.TemporaryDirectory(prefix='Network Sharer 搬移 ',dir='/private/tmp') as temp:
    app=Path(temp)/'另一位置'/'网络共享器.app'; app.parent.mkdir()
    run('/usr/bin/ditto',APP,app)
    run('/usr/bin/codesign','--verify','--deep','--strict',app)
    info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
    assert info['LSMinimumSystemVersion']=='14.0'
    executable=app/'Contents/MacOS'
    macho=[]
    for path in app.rglob('*'):
        if path.is_symlink():
            resolved=path.resolve(strict=True)
            assert resolved.is_relative_to(app.resolve()),str(path)
        elif path.is_file():
            assert path.stat().st_nlink==1,str(path)
            magic=path.read_bytes()[:4]
            if magic in (b'\xcf\xfa\xed\xfe',b'\xca\xfe\xba\xbe',b'\xbe\xba\xfe\xca'):
                macho.append(path)
    assert len(macho)>=8,len(macho)
    dependencies=[]
    for binary in macho:
        arch=run('/usr/bin/lipo','-archs',binary).stdout.split()
        assert 'arm64' in arch,(binary,arch)
        lines=run('/usr/bin/otool','-arch','arm64','-L',binary).stdout.splitlines()[1:]
        ids=run('/usr/bin/otool','-arch','arm64','-D',binary).stdout.splitlines()[1:]
        own_id=ids[0].strip() if ids else ''
        for line in lines:
            dep=line.strip().split(' (compatibility version',1)[0]
            if dep==own_id: continue
            if dep.startswith('@rpath/'):
                resolved=app/'Contents/Frameworks'/dep[len('@rpath/'):]
                assert resolved.exists(),(binary,dep)
            elif dep.startswith('@loader_path/'):
                resolved=(binary.parent/dep[len('@loader_path/'):]).resolve()
                assert resolved.exists() and resolved.is_relative_to(app.resolve()),(binary,dep)
            elif dep.startswith('@executable_path/'):
                resolved=(executable/dep[len('@executable_path/'):]).resolve()
                assert resolved.exists() and resolved.is_relative_to(app.resolve()),(binary,dep)
            else:
                assert dep.startswith('/System/Library/') or dep.startswith('/usr/lib/'),(binary,dep)
            dependencies.append(dep)
    for name in ('HotspotLab','mobile_identity','mock_dispatcher','session_supervisor','subnet_guard','lease_store','socks_gateway','prl_naptd'):
        build=run('/usr/bin/vtool','-show-build',executable/name).stdout
        minima=re.findall(r'\bminos\s+(\d+(?:\.\d+)*)',build)
        assert minima and all(tuple(map(int,v.split('.'))) <= (14,0) for v in minima),(name,minima)
    run(executable/'mobile_identity','--ports')
    isolated=dict(env,NETWORKSHARER_TEST_DISPATCHER=str(executable/'mock_dispatcher'),
                  NETWORKSHARER_TEST_SHIM=str(app/'Contents/Resources/private_runtime.dylib'))
    result=subprocess.run(['/usr/bin/python3',str(ROOT/'Tests/test_parallels_isolation.py')],env=isolated,
                          check=True,capture_output=True,text=True,timeout=20)
    dns_env=dict(env,NETWORKSHARER_TEST_GATEWAY=str(executable/'socks_gateway'))
    dns=subprocess.run(['/usr/bin/python3',str(ROOT/'Tests/test_dns_resolver.py')],env=dns_env,
                       check=True,capture_output=True,text=True,timeout=20)
    print(f'Relocated bundle: {len(macho)} Mach-O files, {len(dependencies)} dependencies, '
          'symlinks, signatures, arm64 and macOS 14 targets verified')
    print(result.stdout.strip())
    print(dns.stdout.strip())
