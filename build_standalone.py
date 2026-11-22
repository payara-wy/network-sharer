#!/usr/bin/env python3
"""Build an isolated Apple Silicon candidate; not a signed public release."""
from pathlib import Path
import os, plistlib, re, shutil, subprocess, tempfile

ROOT=Path(__file__).resolve().parent
GLIB=Path(os.environ.get('NETWORKSHARER_GLIB_PREFIX','/private/tmp/networksharer-deps/macports-glib/opt/local'))
RUNTIME=Path(os.environ.get('NETWORKSHARER_PROTO_RUNTIME','/private/tmp/networksharer-deps/runtime-macos14'))
OUTPUT=Path(os.environ.get('NETWORKSHARER_OUTPUT_DIR',str(ROOT/'build/standalone-candidate'))).resolve()
APP=OUTPUT/'局域网代理共享器.app'
MACOS=APP/'Contents/MacOS'
RES=APP/'Contents/Resources'
SOURCE=ROOT/'ThirdParty/libslirp'

def run(*cmd):
    if cmd and cmd[0]=='/usr/bin/swiftc':
        cache=str(OUTPUT/'swift-module-cache')
        cmd=(cmd[0],'-module-cache-path',cache,'-Xcc','-fmodules-cache-path='+cache,*cmd[1:])
    subprocess.run(cmd,cwd=ROOT,check=True,env={**os.environ,'MACOSX_DEPLOYMENT_TARGET':'14.0','TMPDIR':'/private/tmp'})

def prepare_icon(destination):
    existing=ROOT/'Assets/AppIcon.icns'
    if existing.is_file():
        shutil.copy2(existing,destination); return
    with tempfile.TemporaryDirectory(prefix='networksharer-icon-') as directory:
        work=Path(directory)
        run('/usr/bin/swiftc','-target','arm64-apple-macosx14.0','-O','-framework','AppKit',
            str(ROOT/'Sources/make_icon.swift'),'-o',str(work/'make_icon'))
        run(str(work/'make_icon'),str(work/'icon.png'))
        iconset=work/'AppIcon.iconset'; iconset.mkdir()
        for size in (16,32,128,256,512):
            for scale in (1,2):
                name=f'icon_{size}x{size}'+('@2x' if scale==2 else '')+'.png'
                run('/usr/bin/sips','-z',str(size*scale),str(size*scale),str(work/'icon.png'),
                    '--out',str(iconset/name))
        run('/usr/bin/iconutil','-c','icns',str(iconset),'-o',str(destination))

def validate_macho(path):
    arch=subprocess.run(['/usr/bin/lipo','-archs',str(path)],capture_output=True,text=True,check=True).stdout.split()
    if 'arm64' not in arch: raise RuntimeError('Missing Apple Silicon architecture: '+str(path))
    commands=subprocess.run(['/usr/bin/otool','-arch','arm64','-l',str(path)],capture_output=True,text=True,check=True).stdout
    versions=re.findall(r'\bminos\s+(\d+(?:\.\d+){0,2})',commands)
    if not versions: versions=re.findall(r'\bversion\s+(\d+(?:\.\d+){0,2})',commands.split('LC_VERSION_MIN_MACOSX',1)[-1][:180])
    if not versions or any(tuple(map(int,v.split('.')))>(14,0,0) for v in versions):
        raise RuntimeError('Incompatible or unknown minimum system version: '+str(path)+' '+repr(versions))
    listing=subprocess.run(['/usr/bin/otool','-arch','arm64','-L',str(path)],capture_output=True,text=True,check=True).stdout
    for line in listing.splitlines()[1:]:
        dep=line.strip().split(' (compatibility version',1)[0]
        if dep.startswith(('/System/Library/','/usr/lib/')): continue
        if dep.startswith('@loader_path/') and (path.parent/dep[len('@loader_path/'):]).is_file(): continue
        # Apple ships its Swift runtime in the system on macOS 14.
        if dep.startswith('@rpath/libswift') and '/usr/lib/swift' in commands: continue
        raise RuntimeError('Missing or external dependency '+dep+' in '+str(path))

def main():
    if APP.exists():
        ps=subprocess.run(['/bin/ps','-axo','comm='],capture_output=True,text=True,check=True).stdout
        if str(APP)+'/' in ps: raise RuntimeError('Candidate application is running.')
        shutil.rmtree(APP)
    MACOS.mkdir(parents=True); RES.mkdir(parents=True)
    for name in ('libglib-2.0.0.dylib','libiconv.2.dylib','libintl.8.dylib','libpcre2-8.0.dylib'):
        src=RUNTIME/name
        if not src.is_file(): raise RuntimeError('Missing open-source runtime: '+str(src))
        shutil.copy2(src,MACOS/name)
    meson=(SOURCE/'meson.build').read_text()
    files=re.findall(r"'((?:src/)[^']+\.c)'",meson.split('sources = [',1)[1].split(']',1)[0])
    if len(files)!=31: raise RuntimeError('Unexpected network core sources')
    run('/usr/bin/clang','-dynamiclib','-arch','arm64','-O2','-mmacosx-version-min=14.0',
        '-DBUILDING_LIBSLIRP','-DG_LOG_DOMAIN="Slirp"','-I'+str(SOURCE/'src'),
        '-I'+str(GLIB/'include/glib-2.0'),'-I'+str(GLIB/'lib/glib-2.0/include'),
        '-install_name','@loader_path/libslirp.0.dylib',*[str(SOURCE/name) for name in files],
        str(MACOS/'libglib-2.0.0.dylib'),'-lresolv','-o',str(MACOS/'libslirp.0.dylib'))
    run('/usr/bin/clang','-arch','arm64','-O2','-mmacosx-version-min=14.0','-I'+str(SOURCE/'src'),
        'Sources/standalone_bridge.c','Sources/standalone_leases.c',str(MACOS/'libslirp.0.dylib'),'-o',str(MACOS/'standalone_bridge'))
    for name in ('socks_gateway','session_supervisor','subnet_guard','lease_store'):
        run('/usr/bin/clang','-arch','arm64','-O2','-mmacosx-version-min=14.0','-pthread',
            'Sources/'+name+'.c','-o',str(MACOS/name))
    run('/usr/bin/swiftc','-target','arm64-apple-macosx14.0','-O','-framework','IOKit','-framework','CoreFoundation',
        'Sources/mobile_identity.swift','-o',str(MACOS/'mobile_identity'))
    run('/usr/bin/swiftc','-target','arm64-apple-macosx14.0','-parse-as-library','-swift-version','5','-O',
        '-framework','SwiftUI','-framework','AppKit','-framework','SystemConfiguration',
        'Sources/HotspotLab.swift','Sources/LANProxySupport.swift','Sources/SharingView.swift','-o',str(MACOS/'HotspotLab'))
    for name in ('engine.sh','reconnect_helpers.sh'): shutil.copy2(ROOT/'Sources'/name,RES/name)
    prepare_icon(RES/'AppIcon.icns')
    notices=RES/'ThirdParty'; notices.mkdir()
    for required in ('GLib-LGPL.txt','libiconv-LGPL.txt','gettext-LGPL.txt',
                     'PCRE2-LICENSE.md','PCRE2-SLJIT-LICENSE.txt','SOURCES.md'):
        notice=ROOT/'ThirdParty/RuntimeLicenses'/required
        if not notice.is_file() or notice.stat().st_size<100:
            raise RuntimeError('Missing or empty runtime notice: '+str(notice))
    shutil.copytree(ROOT/'ThirdParty/RuntimeLicenses',notices/'RuntimeLicenses')
    shutil.copytree(SOURCE,notices/'libslirp')
    info={'CFBundleDevelopmentRegion':'zh_CN','CFBundleDisplayName':'局域网代理共享器',
          'CFBundleExecutable':'HotspotLab','CFBundleIdentifier':'com.local.lansharer',
          'CFBundleName':'局域网代理共享器','CFBundleIconFile':'AppIcon.icns','CFBundlePackageType':'APPL',
          'CFBundleShortVersionString':'1.0','CFBundleVersion':'1','LSMinimumSystemVersion':'14.0',
          'NSHighResolutionCapable':True}
    (APP/'Contents/Info.plist').write_bytes(plistlib.dumps(info,sort_keys=False))
    for item in MACOS.iterdir():
        validate_macho(item)
        run('/usr/bin/codesign','--force','--sign','-',str(item))
    run('/usr/bin/codesign','--force','--sign','-',str(APP))
    run('/usr/bin/codesign','--verify','--deep','--strict',str(APP))
    print('Candidate:',APP)

if __name__=='__main__': main()
