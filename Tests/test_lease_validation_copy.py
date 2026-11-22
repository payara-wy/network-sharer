#!/usr/bin/env python3
"""Exercise the disposable app preparation without creating network interfaces."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import uuid
import test_standalone_feth_sessions as test

source_root=Path(__file__).resolve().parents[1]
source_app=Path(os.environ.get('NETWORKSHARER_TEST_APP',source_root/'build'/'standalone-candidate'/'局域网代理共享器.app'))
source_engine=source_app/'Contents/Resources/engine.sh'
before=hashlib.sha256(source_engine.read_bytes()).digest()
workspace=Path('/private/tmp')/('networksharer-validation-'+str(uuid.uuid4()).upper())
workspace.mkdir(mode=0o700)
try:
    root=workspace/'root'; app=root/'build'/'局域网代理共享器正式版'/'局域网代理共享器.app'
    app.parent.mkdir(parents=True); (root/'Tests').mkdir()
    shutil.copy2(source_root/'Sources/lease_store.c',root/'Tests/lease_store.c')
    subprocess.run(['/usr/bin/ditto',str(source_app),str(app)],check=True)
    test.ROOT=root; test.APP=app; test.ENGINE=app/'Contents/Resources/engine.sh'
    parent=workspace/'synthetic-leases'
    test.prepare_isolated_lease_test(parent)
    assert str(parent/'com.local.lansharer') in test.ENGINE.read_text()
    assert hashlib.sha256(source_engine.read_bytes()).digest()==before
finally:
    shutil.rmtree(workspace)
print('Lease validation: disposable app copy rebuilt and signed; original app unchanged')
