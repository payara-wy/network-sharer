#!/usr/bin/env python3
"""Compare target and test-output hashes without modifying any tracked file."""
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
audit=ROOT/'build/audit-20261120-readonly'
manifest=json.loads((audit/'evidence/frozen-hashes.json').read_text())
changed=[]
for name,digest in manifest.items():
    path=ROOT/name
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
        changed.append(name)
allowed=('Tests/run_readonly_audit.py','Tests/audit_io_interpose.c')
unexpected=[name for name in changed if name not in allowed]
result={'frozen_files':len(manifest),'changed':changed,
        'unexpected_source_or_bundle_changes':unexpected,
        'target_changed_during_test':bool(unexpected)}
print(json.dumps(result,ensure_ascii=False,indent=2))
if unexpected: sys.exit(1)
