#!/usr/bin/env python3
"""Check the controller's LAN-proxy argument validation without root.

Only the root guard is removed in a disposable copy; the validation code under
test runs unchanged. The copy points at an empty bundle so a successful
validation stops at the component check instead of starting a session.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'Sources/engine.sh').read_text()

with tempfile.TemporaryDirectory(prefix='lanproxy-engine-args-',dir='/private/tmp') as temporary:
    root=Path(temporary)
    # Keep the script's own layout: <contents>/Resources/engine.sh
    resources=root/'Contents/Resources'; resources.mkdir(parents=True)
    script=resources/'engine.sh'
    guard="[ \"$(/usr/bin/id -u)\" = 0 ] || die '需要管理员权限。'"
    assert source.count(guard)==1,'root guard changed; update the test'
    script.write_text(source.replace(guard,': # root guard removed for this test'))
    script.chmod(0o755)
    (resources/'reconnect_helpers.sh').write_text((ROOT/'Sources/reconnect_helpers.sh').read_text())

    def launch(*ports,lan=None):
        env=dict(os.environ)
        env.pop('NAPTD_LAN_PROXY_PORT',None)
        if lan is not None: env['NAPTD_LAN_PROXY_PORT']=lan
        return subprocess.run(['/bin/bash',str(script),'launch',str(os.getuid()),str(os.getpid()),'en0','direct','0',
                               '1.1.1.1','-',*ports],env=env,capture_output=True,text=True,timeout=30)

    # No downstream port and no LAN proxy: rejected before any setup.
    result=launch()
    assert result.returncode!=0 and '局域网代理' in result.stderr,result.stderr
    # Zero means "not enabled", so no ports and no proxy is still rejected.
    result=launch(lan='0')
    assert result.returncode!=0 and '局域网代理' in result.stderr,result.stderr
    # Other invalid LAN ports are rejected outright.
    for value in ('70000','abc','-1'):
        result=launch(lan=value)
        assert result.returncode!=0 and '局域网代理端口' in result.stderr,(value,result.stderr)
    # A LAN port equal to the upstream SOCKS5 port would collide.
    result=subprocess.run(['/bin/bash',str(script),'launch',str(os.getuid()),str(os.getpid()),'en0','socks5','1082',
                           '1.1.1.1','-'],env=dict(os.environ,NAPTD_LAN_PROXY_PORT='1082'),
                          capture_output=True,text=True,timeout=30)
    assert result.returncode!=0 and '局域网代理端口' in result.stderr,result.stderr
    # A valid proxy-only request passes validation and stops at the missing
    # application components, proving no port list is required.
    result=launch(lan='1080')
    assert result.returncode!=0 and '应用组件缺失' in result.stderr,result.stderr
    # The same holds with one downstream port selected.
    result=launch('en7',lan='1080')
    assert result.returncode!=0 and '应用组件缺失' in result.stderr,result.stderr
    # Without a LAN port a downstream port is still required.
    result=launch('en7')
    assert result.returncode!=0 and '应用组件缺失' in result.stderr,result.stderr
print('Engine LAN arguments: proxy-only launch accepted, invalid or colliding ports rejected, port list optional only with the LAN proxy')
