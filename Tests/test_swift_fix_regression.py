#!/usr/bin/env python3
"""Regression for canonical LAN port display and concurrent command draining.

Uses the real Swift sources from this branch and synthetic states only; it does
not create a sharing session or open an admin prompt.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
work=Path(tempfile.mkdtemp(prefix='swift-fix-',dir=ROOT/'build'))
cache=work/'cache'; cache.mkdir()
env=dict(os.environ,TMPDIR=str(work),CLANG_MODULE_CACHE_PATH=str(cache))
model=(ROOT/'Sources/HotspotLab.swift').read_text().split('@main struct HotspotLabApp: App',1)[0]
(work/'Model.swift').write_text(model)
driver=r'''
import Foundation
import AppKit

struct EmptyStore: LANCredentialStore {
    func load() throws -> LANCredentials? { nil }
    func save(_ value: LANCredentials) throws { }
}

@main struct SwiftFixTests {
    @MainActor static func main() throws {
        let model=HotspotModel(credentialStore: EmptyStore(), observesSystem: false)
        model.lanProxyEnabled=true
        model.lanProxyUsername="Mac"; model.lanProxyPassword="x"
        model.lanProxyPort="+1080"
        model.wifiAddress="192.0.2.10"
        model.applySessionState(["state":"running","lan_ready":"1","lan_port":"+1080","bridge":""])
        assert(model.lanPortNumber==1080)
        assert(model.lanPortText=="1080","display must be canonical, got \(model.lanPortText)")
        assert(model.lanCheck.detail.contains(":1080"),model.lanCheck.detail)
        assert(model.lanProxyAddress.hasSuffix(":1080"),model.lanProxyAddress)
        model.normalizeLanPort()
        assert(model.lanProxyPort=="1080")
        print("PASS canonical port display")

        // Both pipes fill before either closes: sequential reads deadlocked.
        let executable=CommandLine.arguments[1]
        let result=runCommand("/bin/sh",[executable])
        assert(result.status==0)
        assert(result.output.contains("OUT-START"),String(result.output.prefix(80)))
        assert(result.error.count>=700000,"stderr was truncated: \(result.error.count)")
        print("PASS concurrent output draining")
    }
}
'''
(work/'Driver.swift').write_text(driver)
binary=work/'swift-fix-tests'
subprocess.run(['/usr/bin/swiftc','-parse-as-library','-swift-version','5','-target','arm64-apple-macosx14.0',
                '-module-cache-path',str(cache),'-Xcc','-fmodules-cache-path='+str(cache),
                '-framework','SwiftUI','-framework','AppKit','-framework','SystemConfiguration',
                str(work/'Model.swift'),str(ROOT/'Sources/LANProxySupport.swift'),
                str(ROOT/'Sources/SharingView.swift'),str(work/'Driver.swift'),'-o',str(binary)],
               check=True,env=env,timeout=600)
# A child that fills stderr first and only then writes stdout.
script=work/'pipe-fill.sh'
script.write_text('#!/bin/sh\ni=0\nwhile [ $i -lt 12000 ]; do printf "%064d\\n" "$i" >&2; i=$((i+1)); done\nprintf "OUT-START\\n"\n')
script.chmod(0o755)
subprocess.run([str(binary),str(script)],check=True,env=env,timeout=60)
print('Swift fixes verified')
