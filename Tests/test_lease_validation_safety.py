#!/usr/bin/env python3
"""The privileged lease integration test must edit only a disposable app copy."""
from pathlib import Path
import shutil
import uuid
import test_feth_sessions as test

workspace=Path('/private/tmp')/('networksharer-validation-'+str(uuid.uuid4()).upper())
workspace.mkdir(mode=0o700)
try:
    root=workspace/'root'
    app=root/'build'/'网络共享器正式版'/'网络共享器.app'
    engine=app/'Contents/Resources/engine.sh'
    engine.parent.mkdir(parents=True)
    source='lease=/private/var/db/com.local.networksharer/dhcp-leases.ini\nallow=/private/var/db/com.local.networksharer\n'
    engine.write_text(source)
    test.ROOT=root; test.APP=app; test.ENGINE=engine
    commands=[]; test.run=lambda *args,**kwargs: commands.append(args)
    test.prepare_isolated_lease_test(workspace/'leases')
    modified=engine.read_text()
    assert '/private/var/db/com.local.networksharer' not in modified
    assert modified.count(str(workspace/'leases'/'com.local.networksharer'))==2
    assert len(commands)==3 and str(root) in str(commands[0])

    shutil.rmtree(app)
    outside=workspace/'outside.app'; outside_engine=outside/'Contents/Resources/engine.sh'
    outside_engine.parent.mkdir(parents=True); outside_engine.write_text(source)
    app.symlink_to(outside,target_is_directory=True)
    try: test.prepare_isolated_lease_test(workspace/'leases')
    except RuntimeError: pass
    else: raise AssertionError('an external app symlink was accepted')
    assert outside_engine.read_text()==source
finally:
    shutil.rmtree(workspace)
print('Lease validation: only a disposable app copy can be modified')
