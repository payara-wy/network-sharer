#!/usr/bin/env python3
"""Build the local, optional admin-authorized feth integration test UI."""
from pathlib import Path
import plistlib
import os
import re
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
APP=Path(os.environ.get('NETWORKSHARER_VALIDATOR_OUTPUT',str(ROOT/'build'/'局域网代理共享器验证.app')))
PRODUCT=Path(os.environ['NETWORKSHARER_CANDIDATE_APP'])
if not PRODUCT.is_dir(): raise RuntimeError('Build the main app before building the validator')
if APP.exists(): shutil.rmtree(APP)
macos=APP/'Contents/MacOS'; macos.mkdir(parents=True)
template=APP/'Contents/Resources/validation-root'
(template/'Tests').mkdir(parents=True)
(template/'build'/'局域网代理共享器正式版').mkdir(parents=True)
shutil.copy2(ROOT/'Tests/test_standalone_feth_sessions.py',template/'Tests/test_feth_sessions.py')
shutil.copy2(ROOT/'Sources/lease_store.c',template/'Tests/lease_store.c')
shutil.copytree(PRODUCT,template/'build'/'局域网代理共享器正式版'/'局域网代理共享器.app',symlinks=True)
wifi=os.environ.get('NETWORKSHARER_WIFI_DEVICE','')
if not wifi:
    output=subprocess.check_output(['/usr/sbin/networksetup','-listallhardwareports'],text=True)
    match=re.search(r'Hardware Port: Wi-Fi\s+Device: (en[0-9]+)',output)
    if not match: raise RuntimeError('No Wi-Fi interface found')
    wifi=match.group(1)
if not re.fullmatch(r'en[0-9]+',wifi): raise RuntimeError('Invalid Wi-Fi interface')
subprocess.run(['/usr/bin/swiftc','-target','arm64-apple-macosx14.0','-swift-version','5','-parse-as-library',
                '-module-cache-path','/private/tmp/hotspot-swift-cache',
                '-Xcc','-fmodules-cache-path=/private/tmp/hotspot-swift-cache',
                '-framework','SwiftUI','-framework','AppKit',str(ROOT/'Tests/FethValidationApp.swift'),
                '-o',str(macos/'NetworkSharerValidation')],check=True)
subprocess.run(['/usr/bin/clang','-mmacosx-version-min=14.0','-O2','-Wall','-Wextra',
                str(ROOT/'Tests/feth_dhcp_probe.c'),'-o',str(template/'build/networksharer-feth-dhcp-probe')],check=True)
result_dir=Path(tempfile.mkdtemp(prefix='networksharer-validation-result-',dir='/private/tmp'))
info={'CFBundleExecutable':'NetworkSharerValidation','CFBundleIdentifier':os.environ.get('NETWORKSHARER_VALIDATOR_ID','com.local.lansharer.validation'),
      'CFBundleName':'网络共享器本地验证','CFBundlePackageType':'APPL','CFBundleShortVersionString':'1.0',
      'ResultPath':str(result_dir/'result.json'),
      'WiFiDevice':wifi,'LSMinimumSystemVersion':'14.0'}
(APP/'Contents/Info.plist').write_bytes(plistlib.dumps(info))
subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(APP)],check=True)
print(APP)
print('Validation result:',result_dir/'result.json')
