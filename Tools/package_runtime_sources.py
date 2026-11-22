#!/usr/bin/env python3
"""Package verified matching open-source runtime source materials.

This creates a separate source archive. It does not sign, notarize, publish,
or assert that every distribution obligation has been met.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import tarfile

ROOT = Path(__file__).resolve().parents[1]
LICENSES = ROOT/'ThirdParty/RuntimeLicenses'
LIBSLIRP = ROOT/'ThirdParty/libslirp'

# Source hashes are taken from the signed package recipes or the official
# MacPorts GitHub Release asset metadata, respectively.
SOURCES = {
    'glib-2.88.3.tar.xz': ('ab24d24e698dfa1e408b7bcdb508f4aafc906185a8b8ce72fdf79bbbdc9b383b', 'https://download.gnome.org/sources/glib/2.88/glib-2.88.3.tar.xz', 'sources'),
    'libiconv-1.19.tar.gz': ('88dd96a8c0464eca144fc791ae60cd31cd8ee78321e67397e25fc095c4a19aa6', 'https://ftp.gnu.org/gnu/libiconv/libiconv-1.19.tar.gz', 'sources'),
    'gettext-1.0.tar.xz': ('71132a3fb71e68245b8f2ac4e9e97137d3e5c02f415636eb508ae607bc01add7', 'https://ftp.gnu.org/gnu/gettext/gettext-1.0.tar.xz', 'sources'),
    'pcre2-10.49.tar.bz2': ('53c156e1ba416a20da8e65395daa132da0d80e76910424caca3fcdae7831d384', '*****', 'sources'),
    'MacPorts-2.12.2.tar.bz2': ('b8e62e60b201cd31538c9834cdf6bd25c720b049703d3494727e638e980a8a8e', '*****', 'macports-base'),
    'MacPorts-2.12.5.tar.bz2': ('a63be50fc453d261752d4e82deb28c9f3bd26517385a93892fee24bc8da9d661', '*****', 'macports-base'),
    'MacPorts-2.12.6.tar.bz2': ('d4d77de931a0442d0d144e1b3033b6285d51091b9d9e6f73c4e02e3627be29a6', '*****', 'macports-base'),
    'MacPorts-2.12.7.tar.bz2': ('6a3730de846bb78e3fb4ced2ed8d13f777e6aca2ab2f59cade9ca0d549ccc4ba', '*****', 'macports-base'),
}

def file_sha256(path):
    digest=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):
            digest.update(block)
    return digest.hexdigest()

def verify_groups():
    for manifest in sorted((LICENSES/'macports-port-sources').glob('*/groups/MANIFEST.json')):
        entries=json.loads(manifest.read_text())
        for name,record in entries.items():
            if Path(name).name!=name: raise ValueError('unsafe group path')
            data=(manifest.parent/name).read_bytes()
            gitblob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            if gitblob!=record['git_blob_sha1']: raise ValueError('PortGroup mismatch: '+str(manifest.parent/name))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--dependencies',type=Path,default=Path('/private/tmp/networksharer-deps'))
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    output=args.output.resolve()
    source_paths=[]
    for name,(expected,url,directory) in SOURCES.items():
        file=args.dependencies/directory/name
        if not file.is_file() or file_sha256(file)!=expected:
            raise ValueError('Missing or mismatched source archive: '+str(file)+' ('+url+')')
        source_paths.append((file,directory,name))
    verify_groups()
    if not (LIBSLIRP/'LICENSE').is_file() or not (LICENSES/'SOURCES.md').is_file():
        raise ValueError('Missing license/source information')
    output.parent.mkdir(parents=True,exist_ok=True)
    if output.exists(): raise FileExistsError('Refusing to overwrite existing output: '+str(output))
    temporary=output.with_name(output.name+'.partial')
    if temporary.exists(): raise FileExistsError('Remove stale partial output manually: '+str(temporary))
    try:
        with tarfile.open(temporary,'w',dereference=False) as archive:
            archive.add(LICENSES,arcname='network-sharer-third-party/ThirdParty/RuntimeLicenses',recursive=True)
            archive.add(LIBSLIRP,arcname='network-sharer-third-party/ThirdParty/libslirp',recursive=True)
            for tool in ('package_runtime_sources.py','prepare_runtime.py'):
                archive.add(ROOT/'Tools'/tool,arcname='network-sharer-third-party/Tools/'+tool,recursive=False)
            for file,directory,name in source_paths:
                archive.add(file,arcname='network-sharer-third-party/upstream/'+directory+'/'+name,recursive=False)
        os.replace(temporary,output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    print(output)
    print('SHA-256:',file_sha256(output))
    print('Size:',output.stat().st_size)

if __name__=='__main__': main()
