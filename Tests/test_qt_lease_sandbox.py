#!/usr/bin/env python3
"""Test synthetic Qt lease writes using the candidate's actual sandbox policy.

This does not run prl_naptd, create network interfaces or require administrator
privileges. The Qt fixture is deliberately limited to the tested Qt 5.15.19 ABI.
"""
import configparser
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'build'/'网络共享器正式版'/'网络共享器.app'
FRAMEWORK=APP/'Contents/Frameworks/QtCore.framework'
SHIM=APP/'Contents/Resources/private_runtime.dylib'
ENGINE=(ROOT/'Sources/engine.sh').read_text()
assert 'PARALLELS_CONFIG_DIR="$qt_config"' in ENGINE
library=FRAMEWORK/'Versions/5/QtCore'
dependencies=subprocess.run(['/usr/bin/otool','-arch','arm64','-L',str(library)],
                            capture_output=True,text=True,check=True).stdout
if 'current version 5.15.19' not in dependencies:
    raise RuntimeError('The local Qt ABI fixture is only validated with Qt 5.15.19')

with tempfile.TemporaryDirectory(prefix='networksharer-qt-lease-',dir='/private/tmp') as tmp:
    root=Path(tmp); root.chmod(0o700)
    frameworks=root/'Frameworks'; frameworks.mkdir()
    shutil.copytree(FRAMEWORK,frameworks/'QtCore.framework',symlinks=True)
    shim=root/'private_runtime.dylib'; shutil.copy2(SHIM,shim)
    probe=root/'qt_lease_probe'
    subprocess.run(['/usr/bin/clang++','-std=c++17','-Wall','-Wextra','-F',str(frameworks),
                    str(ROOT/'Tests/qt_lease_probe.cpp'),'-framework','QtCore',
                    '-Wl,-rpath,'+str(frameworks),'-o',str(probe)],check=True)
    store=root/'store'; store.mkdir(mode=0o700)
    target=store/'dhcp-leases.ini'; target.touch(mode=0o600); target.chmod(0o600)
    outside=root/'outside'; outside.write_text('unchanged')
    previous=None; killed=0; extras=set()

    for cycle in range(27):
        runtime=root/f'runtime-{cycle}'; runtime.mkdir(mode=0o700)
        qt=runtime/'qt-config'; qt.mkdir(mode=0o700)
        alias=qt/('.parallels_dhcp_leases' if cycle==1 else 'parallels_dhcp_leases')
        alias.symlink_to(target)
        profile=ENGINE.split('\nprofile="',1)[1].split('"\nstub_profile=',1)[0].replace('\\"','"')
        for key,value in {'$qt_config':str(qt),'/private/var/db/com.local.networksharer':str(store),
                          '$dispatcher_name':'com.local.networksharer.test.dispatcher',
                          '$service_name':'com.local.networksharer.test.service',
                          '$relay_tcp':'40001','$relay_udp':'40002'}.items():
            profile=profile.replace(key,value)
        assert '$' not in profile
        env=os.environ.copy(); env.pop('NAPTD_CONTROLLER_PID',None)
        env.update(NAPTD_CONFIG_DIR=str(runtime),PARALLELS_CONFIG_DIR=str(qt),DYLD_INSERT_LIBRARIES=str(shim))
        value=f'cycle-{cycle}-'+('x'*30000)
        args=['/usr/bin/sandbox-exec','-p',profile,str(probe),str(alias),value]
        if cycle<2:
            p=subprocess.run(args,env=env,capture_output=True,text=True,timeout=10)
            assert p.returncode==0 and 'status=0' in p.stdout,(p.returncode,p.stderr)
            link=store/'escape'; link.symlink_to(outside)
            denial=subprocess.run(['/usr/bin/sandbox-exec','-p',profile,'/bin/sh','-c',
                                   'printf changed > "$1"','sandbox-check',str(link)],
                                  capture_output=True,text=True,timeout=5)
            assert denial.returncode!=0 and outside.read_text()=='unchanged'
            link.unlink()
        else:
            p=subprocess.Popen(args,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            time.sleep((0.001,0.003,0.01,0.025,0.05)[cycle%5])
            if p.poll() is None: p.kill(); killed+=1
            p.wait(timeout=10)
        parser=configparser.ConfigParser(interpolation=None)
        parser.read_string(target.read_text()); current=parser.get('vnic0','test')
        assert current in (value,previous)
        previous=current
        assert alias.is_symlink() and stat.S_IMODE(target.stat().st_mode)==0o600
        extras.update(x.name for x in store.iterdir() if x.name!='dhcp-leases.ini')
        shutil.rmtree(runtime)
    assert killed and not extras,(killed,extras)
print('Qt lease sandbox: two sessions, symlink boundaries, mode 0600 and',killed,'synthetic crashes checked')
