#!/usr/bin/env python3
"""Check the validator's interface ownership and cleanup decisions without root."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from test_standalone_feth_sessions import owned_interfaces, interface_gone

with TemporaryDirectory() as directory:
    root=Path(directory)
    (root/'interfaces').write_text('feth feth91 02:11:22:33:44:01\nfeth feth92 02:11:22:33:44:02\nbridge bridge91 02:11:22:33:44:03\nbridge bridge91 02:11:22:33:44:04\n')
    result=owned_interfaces(root,'bridge91',{'feth0','bridge0'})
    assert result=={'feth91':'02:11:22:33:44:01','feth92':'02:11:22:33:44:02','bridge91':'02:11:22:33:44:04'}
    try: owned_interfaces(root,'bridge91',{'feth91'})
    except RuntimeError: pass
    else: raise AssertionError('existing interface was accepted')
    (root/'interfaces').write_text('feth feth91 02:11:22:33:44:01\n')
    try: owned_interfaces(root,'bridge91',set())
    except RuntimeError: pass
    else: raise AssertionError('incomplete records were accepted')
    with patch('test_standalone_feth_sessions.run',return_value=SimpleNamespace(returncode=1,stdout='')):
        assert interface_gone('feth91','02:11:22:33:44:01')
    with patch('test_standalone_feth_sessions.run',return_value=SimpleNamespace(returncode=0,stdout='\tether 02:11:22:33:44:01\n')):
        assert not interface_gone('feth91','02:11:22:33:44:01')
    with patch('test_standalone_feth_sessions.run',return_value=SimpleNamespace(returncode=0,stdout='\tether 02:11:22:33:44:99\n')):
        assert interface_gone('feth91','02:11:22:33:44:01')
print('Standalone validation ownership and cleanup checks passed')
