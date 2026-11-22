#!/usr/bin/env python3
"""Prepare verified relocatable macOS 14 arm64 runtime dependencies locally.

No system installation or privileged operation is performed. This is a build
preparation tool, not a notarization or public release process.
"""
import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
KEY=ROOT/'ThirdParty/RuntimeLicenses/macports-pubkey.pem'
KEY_SHA256='7f429799b3609b95ef1eb024182c973d35a4e1ef326abea4a0599cfb9ff70c77'
BASE='https://mse.uk.packages.macports.org/'
PACKAGES={
 'glib2':('glib2-2.88.3_1+x11.darwin_23.arm64.tbz2','4f44c6138f0fb02f5b11273283e9cb8a7100d515dd836cbd9e26f4a9bea1f518',('opt/local/lib/libglib-2.0.0.dylib','opt/local/lib/glib-2.0/include/','opt/local/include/glib-2.0/')),
 'libiconv':('libiconv-1.19_0.darwin_23.arm64.tbz2','f3c66266fddbb39e393a0dc398d0489e18f24b25fbfee4d7efc94a489e578258',('opt/local/lib/libiconv.2.dylib',)),
 'gettext-runtime':('gettext-runtime-1.0_0.darwin_23.arm64.tbz2','da2ac494335c50e526f7dedef42cda89ce1375d287b74d3bcdda4bbb4c067d35',('opt/local/lib/libintl.8.dylib',)),
 'pcre2':('pcre2-10.49_0.darwin_23.arm64.tbz2','61a9fb537eaebef74d6e2a211f38f01b0fb2032757f16a4c577b651148cb2ba3',('opt/local/lib/libpcre2-8.0.dylib',)),
}

def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()

def download(url,dest):
 temp=dest.with_name(dest.name+'.part')
 try:
  req=urllib.request.Request(url,headers={'User-Agent':'NetworkSharer-dependency-prepare/1'})
  with urllib.request.urlopen(req,timeout=120) as response,temp.open('xb') as out:
   shutil.copyfileobj(response,out,1024*1024)
  os.replace(temp,dest)
 except BaseException:
  temp.unlink(missing_ok=True)
  raise

def extract_selected(archive,staging,allowed):
 found=set()
 with tarfile.open(archive,'r:bz2') as source:
  for item in source:
   name=item.name[2:] if item.name.startswith('./') else item.name
   p=PurePosixPath(name)
   if p.is_absolute() or '..' in p.parts:raise ValueError('Unsafe archive path: '+name)
   matches=[prefix for prefix in allowed if name==prefix.rstrip('/') or (prefix.endswith('/') and name.startswith(prefix))]
   if not matches:continue
   if item.isdir():continue
   if not item.isfile():raise ValueError('Unexpected archive link or special file: '+name)
   target=staging.joinpath(*p.parts);target.parent.mkdir(parents=True,exist_ok=True)
   with source.extractfile(item) as src,target.open('xb') as out: shutil.copyfileobj(src,out,1024*1024)
   target.chmod(item.mode & 0o777)
   for prefix in matches:found.add(prefix)
 missing=set(allowed)-found
 if missing:raise ValueError('Archive missing required paths: '+repr(sorted(missing)))

def run(*args):subprocess.run(args,check=True)

def main():
 parser=argparse.ArgumentParser()
 parser.add_argument('--packages',type=Path,required=True,help='private download/cache directory')
 parser.add_argument('--output',type=Path,required=True,help='new output directory')
 parser.add_argument('--download-missing',action='store_true')
 args=parser.parse_args()
 cache=args.packages.resolve();dest=args.output.resolve()
 if dest.exists():raise FileExistsError('Refusing to overwrite: '+str(dest))
 if digest(KEY)!=KEY_SHA256:raise ValueError('MacPorts key fingerprint mismatch')
 cache.mkdir(parents=True,exist_ok=True);dest.parent.mkdir(parents=True,exist_ok=True)
 for package,(name,sha,_) in PACKAGES.items():
  archive=cache/name;signature=cache/(name+'.rmd160')
  for path,url in ((archive,BASE+package+'/'+name),(signature,BASE+package+'/'+name+'.rmd160')):
   if not path.is_file():
    if not args.download_missing:raise FileNotFoundError(str(path))
    download(url,path)
  if digest(archive)!=sha:raise ValueError('Package digest mismatch: '+name)
  run('/usr/bin/openssl','dgst','-ripemd160','-verify',str(KEY),'-signature',str(signature),str(archive))
 with tempfile.TemporaryDirectory(prefix='networksharer-runtime-',dir=str(dest.parent)) as temp:
  work=Path(temp);stage=work/'stage';stage.mkdir()
  for package,(name,sha,allowed) in PACKAGES.items():extract_selected(cache/name,stage,allowed)
  result=work/'result';(result/'runtime').mkdir(parents=True)
  prefix=result/'glib';prefix.mkdir()
  shutil.copytree(stage/'opt/local/include',prefix/'include')
  (prefix/'lib/glib-2.0').mkdir(parents=True)
  shutil.copytree(stage/'opt/local/lib/glib-2.0/include',prefix/'lib/glib-2.0/include')
  for name in ('libglib-2.0.0.dylib','libiconv.2.dylib','libintl.8.dylib','libpcre2-8.0.dylib'):
   shutil.copy2(stage/'opt/local/lib'/name,result/'runtime'/name)
  d=result/'runtime'
  run('/usr/bin/install_name_tool','-id','@loader_path/libglib-2.0.0.dylib',
      '-change','/opt/local/lib/libiconv.2.dylib','@loader_path/libiconv.2.dylib',
      '-change','/opt/local/lib/libintl.8.dylib','@loader_path/libintl.8.dylib',
      '-change','/opt/local/lib/libpcre2-8.0.dylib','@loader_path/libpcre2-8.0.dylib',str(d/'libglib-2.0.0.dylib'))
  run('/usr/bin/install_name_tool','-id','@loader_path/libintl.8.dylib',
      '-change','/opt/local/lib/libiconv.2.dylib','@loader_path/libiconv.2.dylib',str(d/'libintl.8.dylib'))
  for name in ('libiconv.2.dylib','libpcre2-8.0.dylib'):
   run('/usr/bin/install_name_tool','-id','@loader_path/'+name,str(d/name))
  for lib in sorted(d.glob('*.dylib')):run('/usr/bin/codesign','--force','--sign','-',str(lib))
  result.rename(dest)
 print('Prepared:',dest)
 print('NETWORKSHARER_GLIB_PREFIX='+str(dest/'glib'))
 print('NETWORKSHARER_PROTO_RUNTIME='+str(dest/'runtime'))

if __name__=='__main__':main()
