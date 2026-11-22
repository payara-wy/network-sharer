#!/usr/bin/env python3
"""Create a drag-to-Applications DMG from a validated application bundle."""
from pathlib import Path
import argparse
import hashlib
import os
import shutil
import subprocess
import tempfile

parser=argparse.ArgumentParser()
parser.add_argument('--app',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
app=args.app.resolve(strict=True)
output=args.output.resolve()
if app.name!='网络共享器.app' or not app.is_dir(): raise ValueError('Expected a 网络共享器.app bundle')
if output.suffix!='.dmg' or output.exists(): raise ValueError('Output must be a new DMG file')
subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],check=True)
output.parent.mkdir(parents=True,exist_ok=True)
with tempfile.TemporaryDirectory(prefix='networksharer-dmg-',dir='/private/tmp') as temp:
    stage=Path(temp)/'stage';stage.mkdir()
    subprocess.run(['/usr/bin/ditto',str(app),str(stage/app.name)],check=True)
    (stage/'Applications').symlink_to('/Applications')
    (stage/'安装说明.txt').write_text('''网络共享器：Apple 芯片 Mac，系统要求 macOS 14 或更高版本。\n\n将“网络共享器”拖入“Applications”文件夹，然后从“应用程序”打开。\n本版本未经过 Apple 公证，首次打开可能被系统拦截；确认文件来源可靠后，可在“系统设置 > 隐私与安全性”中查看打开选项。\n启动共享需要管理员授权。已认证网络是否允许共享取决于网络策略。\n''',encoding='utf-8')
    subprocess.run(['/usr/bin/hdiutil','create','-quiet','-format','UDZO','-volname','网络共享器',
                    '-srcfolder',str(stage),str(output)],check=True)
with output.open('rb') as f:
    h=hashlib.sha256()
    while True:
        chunk=f.read(1024*1024)
        if not chunk:break
        h.update(chunk)
print('DMG:',output)
print('SHA-256:',h.hexdigest())
