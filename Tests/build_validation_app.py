#!/usr/bin/env python3
"""Build the local, optional admin-authorized feth integration test UI."""
from pathlib import Path
import plistlib
import re
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'build'/'网络共享器本地验证.app'
PRODUCT=ROOT/'build'/'网络共享器正式版'/'网络共享器.app'
if not PRODUCT.is_dir(): raise RuntimeError('Build the main app before building the validator')
(ROOT/'results').mkdir(parents=True,exist_ok=True)
if APP.exists(): shutil.rmtree(APP)
macos=APP/'Contents/MacOS'; macos.mkdir(parents=True)
template=APP/'Contents/Resources/validation-root'
(template/'Tests').mkdir(parents=True)
(template/'build'/'网络共享器正式版').mkdir(parents=True)
shutil.copy2(ROOT/'Tests/test_feth_sessions.py',template/'Tests/test_feth_sessions.py')
shutil.copy2(ROOT/'Sources/lease_store.c',template/'Tests/lease_store.c')
shutil.copytree(PRODUCT,template/'build'/'网络共享器正式版'/'网络共享器.app',symlinks=True)
output=subprocess.check_output(['/usr/sbin/networksetup','-listallhardwareports'],text=True)
match=re.search(r'Hardware Port: Wi-Fi\s+Device: (en[0-9]+)',output)
if not match: raise RuntimeError('No Wi-Fi interface found')
subprocess.run(['/usr/bin/swiftc','-target','arm64-apple-macosx14.0','-swift-version','5','-parse-as-library',
                '-module-cache-path','/private/tmp/hotspot-swift-cache',
                '-Xcc','-fmodules-cache-path=/private/tmp/hotspot-swift-cache',
                '-framework','SwiftUI','-framework','AppKit',str(ROOT/'Tests/FethValidationApp.swift'),
                '-o',str(macos/'NetworkSharerValidation')],check=True)
subprocess.run(['/usr/bin/clang','-mmacosx-version-min=14.0','-O2','-Wall','-Wextra',
                str(ROOT/'Tests/feth_dhcp_probe.c'),'-o',str(template/'build/networksharer-feth-dhcp-probe')],check=True)
info={'CFBundleExecutable':'NetworkSharerValidation','CFBundleIdentifier':'com.local.networksharer.validation',
      'CFBundleName':'网络共享器本地验证','CFBundlePackageType':'APPL','CFBundleShortVersionString':'1.0',
      'ResultPath':str(ROOT/'results/feth-session-validation.json'),
      'WiFiDevice':match.group(1),'LSMinimumSystemVersion':'14.0'}
(APP/'Contents/Info.plist').write_bytes(plistlib.dumps(info))
subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(APP)],check=True)
print(APP)
