#!/usr/bin/env python3
"""Exercise reconnection identity matching and interface safety decisions."""
from pathlib import Path
import subprocess

HELPER = Path(__file__).resolve().parents[1]/'Sources/reconnect_helpers.sh'

def shell(code, *args):
    return subprocess.run(['/bin/bash', '-c', 'source "$1"; shift; '+code, 'test', str(HELPER), *args],
                          capture_output=True, text=True, timeout=5)

for spec, expected in [('en7@mobile', 'en7 mobile'), ('en12@mobile', 'en12 mobile'), ('en3', 'en3 fixed'), ('feth1', 'feth1 fixed')]:
    p = shell('decode_port_spec "$1" && printf "%s %s" "$port_iface" "$port_kind"', spec)
    assert p.returncode == 0 and p.stdout == expected, spec
for spec in ('en7;id', 'en7@mobile@mobile', 'bridge0@mobile', 'feth1@mobile', '../en7'):
    assert shell('decode_port_spec "$1"', spec).returncode != 0, spec

first = 'a'*64
second = 'b'*64
def resolve(snapshot):
    return shell('resolve_mobile_iface "$1" "$2"', first, snapshot)
assert resolve('en7 '+first+'\nen3 '+second).stdout.strip() == 'en7'
assert resolve('en18 '+first+'\nen7 '+second).stdout.strip() == 'en18'
assert resolve('en7 '+second).returncode != 0
assert resolve('en7 '+first+'\nen18 '+first).returncode != 0
assert resolve('bridge7 '+first).returncode != 0

def allowed(*args):
    return shell('interface_attach_allowed "$@"', *args).returncode == 0
assert allowed('en7', 'en0', 'utun6', '0', '0')
assert not allowed('en0', 'en0', 'utun6', '0', '0')
assert not allowed('en7', 'en0', 'en7', '0', '0')
assert not allowed('en7', 'en0', 'utun6', '1', '0')
assert not allowed('en7', 'en0', 'utun6', '0', '1')
assert not allowed('en7;id', 'en0', 'utun6', '0', '0')
print('Reconnection checks: stable identity, renumbering, ambiguity and interface safety passed')
