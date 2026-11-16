#!/usr/bin/env python3
"""Build the local macOS app bundle without modifying the extracted daemon."""
from pathlib import Path
import hashlib
import os
import plistlib
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parent
PARALLELS_APP=Path(os.environ.get('NETWORKSHARER_PARALLELS_APP','/Applications/Parallels Desktop.app'))
DAEMON=Path(os.environ.get('NETWORKSHARER_DAEMON',str(PARALLELS_APP/'Contents/MacOS/prl_naptd')))
FRAMEWORKS=Path(os.environ.get('NETWORKSHARER_QT_FRAMEWORKS',str(PARALLELS_APP/'Contents/Frameworks')))
BUILD=Path(os.environ.get('NETWORKSHARER_OUTPUT_DIR',str(ROOT/'build'/'网络共享器正式版'))).resolve()
APP=BUILD/'网络共享器.app'
CONTENTS=APP/'Contents'
MACOS=CONTENTS/'MacOS'
RES=CONTENTS/'Resources'

def run(*args):
    env=os.environ.copy()
    env['MACOSX_DEPLOYMENT_TARGET']='14.0'
    subprocess.run(args,cwd=ROOT,check=True,env=env)

def copy(source,destination):
    destination.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(source,destination,follow_symlinks=False)

def validate_runtime():
    for binary in (DAEMON,FRAMEWORKS/'QtCore.framework/Versions/5/QtCore',
                   FRAMEWORKS/'QtNetwork.framework/Versions/5/QtNetwork'):
        if not binary.is_file(): raise RuntimeError('Required local runtime component is missing: '+str(binary))
        arch=subprocess.run(['/usr/bin/lipo','-archs',str(binary)],capture_output=True,text=True,check=True).stdout.split()
        if 'arm64' not in arch: raise RuntimeError('Runtime component does not include Apple silicon: '+str(binary))
        output=subprocess.run(['/usr/bin/otool','-arch','arm64','-L',str(binary)],capture_output=True,text=True,check=True).stdout
        for line in output.splitlines()[1:]:
            dependency=line.strip().split(' (compatibility version',1)[0]
            if dependency.startswith(('/System/Library/','/usr/lib/','@rpath/QtCore.framework/',
                                      '@rpath/QtNetwork.framework/')): continue
            raise RuntimeError('Unexpected runtime dependency '+dependency+' in '+str(binary))

def ensure_not_running():
    if not APP.exists(): return
    processes=subprocess.run(['/bin/ps','-axo','comm='],capture_output=True,text=True,check=True).stdout.splitlines()
    if any(line.strip().startswith(str(APP)+'/') for line in processes):
        raise RuntimeError('The output application is running. Quit it or choose NETWORKSHARER_OUTPUT_DIR.')

def prepare_icon(destination):
    existing=ROOT/'Assets/AppIcon.icns'
    if existing.is_file():
        copy(existing,destination)
        return
    # The source-only distribution can regenerate the original icon locally.
    with tempfile.TemporaryDirectory(prefix='networksharer-icon-') as directory:
        work=Path(directory)
        run('/usr/bin/swiftc','-target','arm64-apple-macosx14.0','-O','-framework','AppKit',
            str(ROOT/'Sources/make_icon.swift'),'-o',str(work/'make_icon'))
        run(str(work/'make_icon'),str(work/'icon.png'))
        iconset=work/'AppIcon.iconset'
        iconset.mkdir()
        for size in (16,32,128,256,512):
            for scale in (1,2):
                name=f'icon_{size}x{size}'+('@2x' if scale==2 else '')+'.png'
                run('/usr/bin/sips','-z',str(size*scale),str(size*scale),str(work/'icon.png'),
                    '--out',str(iconset/name))
        run('/usr/bin/iconutil','-c','icns',str(iconset),'-o',str(destination))

def main():
    validate_runtime()
    ensure_not_running()
    run('/usr/bin/clang','-mmacosx-version-min=14.0','-O2','-Wall','-Wextra','-pthread','Sources/socks_gateway.c','-o','socks_gateway')
    run('/usr/bin/clang','-mmacosx-version-min=14.0','-O2','-Wall','-Wextra','-pthread','-framework','CoreFoundation',
        'Sources/mock_dispatcher.c','-o','mock_dispatcher')
    run('/usr/bin/clang','-mmacosx-version-min=14.0','-O2','-Wall','-Wextra','-Wno-deprecated-declarations','-dynamiclib',
        '-framework','CoreFoundation','Sources/private_runtime.c','-o','private_runtime.dylib')
    run('/usr/bin/clang','-mmacosx-version-min=14.0','-O2','-Wall','-Wextra',
        'Sources/session_supervisor.c','-o','session_supervisor')
    run('/usr/bin/clang','-mmacosx-version-min=14.0','-O2','-Wall','-Wextra',
        'Sources/subnet_guard.c','-o','subnet_guard')
    run('/usr/bin/clang','-mmacosx-version-min=14.0','-O2','-Wall','-Wextra',
        'Sources/lease_store.c','-o','lease_store')
    BUILD.mkdir(parents=True,exist_ok=True)
    if APP.exists(): shutil.rmtree(APP)
    MACOS.mkdir(parents=True); RES.mkdir(parents=True)
    run('/usr/bin/swiftc','-target','arm64-apple-macosx14.0','-parse-as-library','-swift-version','5','-module-cache-path','/private/tmp/hotspot-swift-cache',
        '-Xcc','-fmodules-cache-path=/private/tmp/hotspot-swift-cache','-O','-framework','SwiftUI','-framework','AppKit','-framework','SystemConfiguration',
        'Sources/HotspotLab.swift','-o',str(MACOS/'HotspotLab'))
    copy(DAEMON,MACOS/'prl_naptd')
    copy(ROOT/'mock_dispatcher',MACOS/'mock_dispatcher')
    copy(ROOT/'socks_gateway',MACOS/'socks_gateway')
    copy(ROOT/'session_supervisor',MACOS/'session_supervisor')
    copy(ROOT/'subnet_guard',MACOS/'subnet_guard')
    copy(ROOT/'lease_store',MACOS/'lease_store')
    run('/usr/bin/swiftc','-target','arm64-apple-macosx14.0','-O','-module-cache-path','/private/tmp/hotspot-swift-cache',
        '-Xcc','-fmodules-cache-path=/private/tmp/hotspot-swift-cache',
        '-framework','IOKit','-framework','CoreFoundation','Sources/mobile_identity.swift','-o',str(MACOS/'mobile_identity'))
    for name in ('QtCore.framework','QtNetwork.framework'):
        shutil.copytree(FRAMEWORKS/name,CONTENTS/'Frameworks'/name,symlinks=True)
    copy(ROOT/'Sources/engine.sh',RES/'engine.sh')
    copy(ROOT/'Sources/reconnect_helpers.sh',RES/'reconnect_helpers.sh')
    copy(ROOT/'private_runtime.dylib',RES/'private_runtime.dylib')
    prepare_icon(RES/'AppIcon.icns')
    copy(ROOT/'Assets/network.desktop.xml',RES/'network.desktop.xml')
    info={'CFBundleDevelopmentRegion':'zh_CN','CFBundleDisplayName':'网络共享器',
          'CFBundleExecutable':'HotspotLab','CFBundleIdentifier':'com.local.networksharer',
          'CFBundleName':'网络共享器','CFBundleIconFile':'AppIcon.icns','CFBundlePackageType':'APPL','CFBundleShortVersionString':'1.0',
          'CFBundleVersion':'1','LSMinimumSystemVersion':'14.0','NSHighResolutionCapable':True}
    (CONTENTS/'Info.plist').write_bytes(plistlib.dumps(info,sort_keys=False))
    original=DAEMON.read_bytes()
    packaged=(MACOS/'prl_naptd').read_bytes()
    assert hashlib.sha256(original).digest()==hashlib.sha256(packaged).digest()
    assert not any('macked.app.dylib' in p.name for p in APP.rglob('*'))
    assert not (RES/'runtime').exists()
    for p in APP.rglob('*'):
        if p.is_symlink() and not p.resolve().is_relative_to(APP.resolve()):
            raise RuntimeError('Bundle symlink escapes app: '+str(p))
        if p.is_file() and not p.is_symlink() and p.stat().st_nlink!=1:
            raise RuntimeError('Bundle file unexpectedly uses hard links: '+str(p))
    run('/usr/bin/codesign','--force','--sign','-',str(APP))
    run('/usr/bin/codesign','--verify','--deep','--strict',str(APP))
    print('Built:',APP)
    print('Daemon SHA-256:',hashlib.sha256(packaged).hexdigest())
    print('All framework symlinks remain inside the app.')

if __name__=='__main__': main()
