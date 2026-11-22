#!/usr/bin/env python3
"""Run the real reconciliation function against isolated synthetic interfaces."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
identity = 'a'*64
different = 'b'*64
engine = (ROOT/'Sources/engine.sh').read_text()
start = engine.index('bridge_has_member() {')
end = engine.index("\nstate=waiting; phase=running;", start)
functions = engine[start:end]

mock = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
p = Path(os.environ['RECONNECT_TEST_STATE'])
s = json.loads(p.read_text())
args = sys.argv[1:]
if args == ['-l']:
    print(' '.join(['en0', 'bridge102', 'bridge0'] + sorted(s['ports'])))
elif args and args[0].startswith('bridge'):
    bridge = args[0]
    if len(args) >= 3 and args[1] in ('addm', 'deletem'):
        members = s['bridges'].setdefault(bridge, [])
        if args[1] == 'addm' and args[2] not in members: members.append(args[2])
        if args[1] == 'deletem' and args[2] in members: members.remove(args[2])
        s.setdefault('operations', []).append(args[1] + ':' + args[2])
        p.write_text(json.dumps(s))
    else:
        print(bridge + ': flags=UP')
        for member in s['bridges'].get(bridge, []): print('\tmember: ' + member + ' flags=3')
elif args and args[0] in s['ports']:
    d = s['ports'][args[0]]
    print(args[0] + ': flags=UP')
    if not d.get('missing_mac'): print('\tether ' + d.get('mac', '02:00:00:00:00:07'))
    if d.get('ip'): print('\tinet ' + d['ip'] + ' netmask 0xffffff00')
    print('\tstatus: ' + ('active' if d.get('active', True) else 'inactive'))
else:
    sys.exit(1)
'''

identity_mock = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
s = json.loads(Path(os.environ['RECONNECT_TEST_STATE']).read_text())
if s.get('scan_error'): sys.exit(1)
for interface, identity in s.get('mobile', []): print(interface, identity)
'''

route_mock = '#!/bin/sh\nprintf "interface: en0\\n"\n'

def snapshot(ports, mobile, members=(), other=(), **kwargs):
    return {'ports': ports, 'mobile': mobile, 'bridges': {'bridge102': list(members), 'bridge0': list(other)}, **kwargs}

port = {'active': True, 'ip': '169.254.10.20', 'mac': '02:00:00:00:00:07'}
with tempfile.TemporaryDirectory(prefix='hotspot-reconnect-test-', dir='/private/tmp') as temporary:
    root = Path(temporary)
    (root/'host-macs').write_text('02:00:00:00:00:03\n02:00:00:00:00:07\n')
    for name, content in [('ifconfig', mock), ('route', route_mock), ('mobile_identity', identity_mock)]:
        target = root/name
        target.write_text(content)
        target.chmod(0o755)
    cases = {
        'initial': snapshot({'en7': port}, [('en7', identity)], ['en7']),
        'gone': snapshot({}, [], []),
        'same': snapshot({'en7': port}, [('en7', identity)], []),
        'renumber': snapshot({'en8': port}, [('en8', identity)], []),
        'ambiguous': snapshot({'en7': port, 'en8': port}, [('en7', identity), ('en8', identity)], []),
        'wrong': snapshot({'en8': port}, [('en8', different)], ['en8']),
        'other': snapshot({'en8': port}, [('en8', identity)], [], ['en8']),
        'addressed': snapshot({'en8': {**port, 'ip':'192.168.10.5'}}, [('en8', identity)], []),
        'scan_error': snapshot({'en8': port}, [], ['en8'], scan_error=True),
        'mixed_gone': snapshot({'en3': {**port, 'mac':'02:00:00:00:00:03'}}, [], ['en3']),
        'mixed_return': snapshot({'en3': {**port, 'mac':'02:00:00:00:00:03'}, 'en8': port}, [('en8', identity)], ['en3']),
        'transient_no_mac': snapshot({'en8': {**port, 'missing_mac': True}}, [('en8', identity)], ['en8']),
        'transient_unlisted_mac': snapshot({'en8': {**port, 'mac': '12:34:56:78:90:ab'}}, [('en8', identity)], ['en8']),
    }
    for name, data in cases.items(): (root/(name+'.json')).write_text(json.dumps(data))
    functions = functions.replace('/sbin/ifconfig', shlex.quote(str(root/'ifconfig')))
    functions = functions.replace('/sbin/route', shlex.quote(str(root/'route')))
    driver = '''set -eu
source __HELPER__
bridge=bridge102; source=en0; dir=__DIR__; device_salt=test
declare -a original_ports port_kinds port_ids port_macs current_ports missing_counts
original_ports[0]=en7; port_kinds[0]=mobile; port_ids[0]=__IDENTITY__; port_macs[0]=-; current_ports[0]=en7; missing_counts[0]=0
portcount=1; needs_mobile=1; portlist=en7; portmap=en7:en7; attached_list=' en7'; state=running; message='共享端口已接入；请在设备上验证网络'
write_state() { :; }
record_interface() { :; }
REFRESH_CALLS=0; REFRESH_FAIL_AT=0
refresh_host_macs() { REFRESH_CALLS=$((REFRESH_CALLS+1)); [ "$REFRESH_CALLS" != "$REFRESH_FAIL_AT" ]; }
fail() { printf '%s\\n' "$*" >&2; return 1; }
__FUNCTIONS__
load_case() { /bin/cp "__DIR__/$1.json" "$RECONNECT_TEST_STATE"; }
expect_members() { /usr/bin/python3 -c 'import json,os,sys; s=json.load(open(os.environ["RECONNECT_TEST_STATE"])); assert s["bridges"]["bridge102"]==sys.argv[1:]' "$@"; }
load_case initial; reconcile_ports; [ "$state" = running ]; expect_members en7
load_case gone; reconcile_ports; [ "$state" = waiting ]; [ "$portmap" = en7:- ]; expect_members
load_case same; reconcile_ports; [ "$state" = running ]; [ "$portmap" = en7:en7 ]; expect_members en7
load_case renumber; reconcile_ports; [ "$state" = running ]; [ "$portmap" = en7:en8 ]; expect_members en8
load_case scan_error; reconcile_ports; [ "$state" = waiting ]; expect_members en8
load_case ambiguous; reconcile_ports; [ "$state" = waiting ]; expect_members
load_case other; reconcile_ports; [ "$state" = waiting ]; expect_members
load_case addressed; reconcile_ports; [ "$state" = waiting ]; expect_members
load_case wrong; reconcile_ports; reconcile_ports; [ "$state" = waiting ]; expect_members
load_case transient_no_mac; reconcile_ports; [ "$state" = waiting ]; expect_members
load_case transient_unlisted_mac; reconcile_ports; [ "$state" = waiting ]; expect_members
load_case renumber; REFRESH_CALLS=0; REFRESH_FAIL_AT=1
reconcile_ports; [ "$state" = waiting ]; expect_members
load_case renumber; REFRESH_CALLS=0; REFRESH_FAIL_AT=2
reconcile_ports; [ "$state" = waiting ]; expect_members
REFRESH_FAIL_AT=0; REFRESH_CALLS=0
load_case renumber; reconcile_ports; [ "$state" = running ]; expect_members en8
original_ports[0]=en7; port_kinds[0]=mobile; port_ids[0]=__IDENTITY__; port_macs[0]=-; current_ports[0]=en7; missing_counts[0]=0
original_ports[1]=en3; port_kinds[1]=fixed; port_ids[1]=-; port_macs[1]=02:00:00:00:00:03; current_ports[1]=en3; missing_counts[1]=0
portcount=2; portlist=en7,en3; portmap=en7:en7,en3:en3; attached_list=' en7 en3'; state=running
load_case mixed_gone; reconcile_ports; [ "$state" = waiting ]; [ "$portmap" = en7:-,en3:en3 ]; expect_members en3
load_case mixed_return; reconcile_ports; [ "$state" = running ]; [ "$portmap" = en7:en8,en3:en3 ]; expect_members en3 en8
printf 'Reconnection controller: unplug, replug, renumber, identity ambiguity and network conflicts passed\\n'
'''
    replacements = {'__HELPER__':shlex.quote(str(ROOT/'Sources/reconnect_helpers.sh')),
                    '__DIR__':shlex.quote(str(root)), '__IDENTITY__':identity, '__FUNCTIONS__':functions}
    for key, value in replacements.items(): driver = driver.replace(key, value)
    env = os.environ.copy(); env['RECONNECT_TEST_STATE'] = str(root/'active.json')
    result = subprocess.run(['/bin/bash'], input=driver, capture_output=True, text=True, errors='replace', env=env, timeout=30)
    print(result.stdout.strip())
    if result.returncode:
        print(result.stderr.strip())
        raise SystemExit(result.returncode)
