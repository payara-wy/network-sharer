#!/usr/bin/env python3
"""Black-box disk IO summary from the completed syscall interposer."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
result=json.loads((ROOT/'build/audit-20261120-readonly/evidence/blackbox-memory-results.json').read_text())
io=result.get('disk_io_interposition',{})
for line in io.get('io_samples',[]): print(line)
print('lease_write_test:',(ROOT/'build/audit-20261120-readonly/evidence/dhcp-write-result.json').read_text())
