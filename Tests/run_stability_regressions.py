#!/usr/bin/env python3
"""Run selected existing tests against a specified candidate, in workspace scratch.
Only fixture paths/caches and binary locations are adapted, not test assertions.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('app',type=Path)
args=parser.parse_args()
app=args.app.resolve(strict=True)
assert app.is_relative_to(ROOT/'build')
work=Path(tempfile.mkdtemp(prefix='stability-regression-',dir=ROOT/'build'))
env={k:v for k,v in os.environ.items() if not k.startswith('NAPTD_')}
env.update(TMPDIR=str(work), PYTHONDONTWRITEBYTECODE='1', NETWORKSHARER_TEST_APP=str(app),
           NETWORKSHARER_TEST_GATEWAY=str(app/'Contents/MacOS/socks_gateway'),
           NETWORKSHARER_TEST_BRIDGE=str(app/'Contents/MacOS/standalone_bridge'))
results={}
for name in ('test_bundle_portability.py','test_dns_resolver.py','test_socks_auth.py',
             'test_local_checks.py','test_session_state.py','test_session_supervisor.py',
             'test_lan_ui.py','test_standalone_packets.py','test_slirp_relay_packets.py','test_standalone_leases.py'):
    text=(ROOT/'Tests'/name).read_text()
    for spelling in ('ROOT=Path(__file__).resolve().parents[1]','ROOT = Path(__file__).resolve().parents[1]',
                     'ROOT = Path(__file__).resolve().parents[1]'):
        text=text.replace(spelling,'ROOT=Path('+repr(str(ROOT))+')')
    text=text.replace("ROOT/'socks_gateway'",'Path('+repr(str(app/'Contents/MacOS/socks_gateway'))+')')
    text=text.replace("'/private/tmp/hotspot-swift-cache'",repr(str(work/'cache')))
    text=text.replace('-fmodules-cache-path=/private/tmp/hotspot-swift-cache','-fmodules-cache-path='+str(work/'cache'))
    text=text.replace("'/private/tmp'",repr(str(work)))
    text=text.replace("source.index('enum CheckLevel {')","source.index('enum CheckLevel')")
    text=text.replace("ROOT / 'build/standalone-udp-final/局域网代理共享器.app'",'Path('+repr(str(app))+')')
    if name=='test_lan_ui.py': text=text.replace("str(work / 'Model.swift'),", "str(work / 'Model.swift'),")
    # Packet tests import a local helper; load only our disposable helper copy.
    script=work/name; script.write_text(text)
    cmd=['/usr/bin/python3','-I','-c',
         'import sys,runpy;sys.path.insert(0,sys.argv[1]);runpy.run_path(sys.argv[2],run_name="__main__")',str(work),str(script)]
    p=subprocess.run(cmd,cwd=ROOT,env=env,capture_output=True,text=True,timeout=180)
    (work/(name+'.log')).write_text(p.stdout+p.stderr)
    results[name]={'pass':p.returncode==0,'exit':p.returncode}
    print(name+': '+('PASS' if not p.returncode else 'FAIL\n'+(p.stdout+p.stderr)[-1200:]),flush=True)
(work/'results.json').write_text(json.dumps(results,indent=2))
print('Report:',work/'results.json',flush=True)
raise SystemExit(0 if all(r['pass'] for r in results.values()) else 1)
