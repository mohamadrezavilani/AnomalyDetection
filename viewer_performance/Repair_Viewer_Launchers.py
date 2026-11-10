"""Restore only known LF/CRLF variants to the installed launcher's exact hashes.

Can run from Git through stdin before pulling a packaging fix. Never changes
private config, keys, core runtime files or database state. All three inputs
must be byte-identical to the manifest apart from newline representation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

NAMES=('Start_Viewer.cmd','Start_Viewer_Standard.cmd','tools/viewer.ps1')


def repair(project):
    project=Path(project).resolve()
    manifest=json.loads((project/'RELEASE_MANIFEST.json').read_text(encoding='utf-8-sig'))
    prepared=[]
    for name in NAMES:
        path=project/name
        if not path.resolve().is_relative_to(project) or path.is_symlink():
            raise ValueError('LAUNCHER_OUTSIDE_PROJECT:'+name)
        original=path.read_bytes();expected=manifest['files_sha256'][name]
        lf=original.replace(b'\r\n',b'\n')
        target=next((data for data in (original,lf,lf.replace(b'\n',b'\r\n'))
            if hashlib.sha256(data).hexdigest()==expected),None)
        if target is None:raise ValueError('LAUNCHER_CONTENT_CHANGED:'+name)
        if target!=original:prepared.append((path,target))
    # Validate every file before writing any. Each replacement is atomic;
    # rerunning is safe even if one later replacement hits a filesystem error.
    for path,target in prepared:
        temporary=None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent,prefix=path.name+'.',suffix='.tmp',delete=False) as stream:
                temporary=Path(stream.name);stream.write(target);stream.flush();os.fsync(stream.fileno())
            temporary.chmod(path.stat().st_mode & 0o777)
            temporary.replace(path)
        finally:
            if temporary is not None:temporary.unlink(missing_ok=True)
    return {'status':'EXACT_LAUNCHER_BYTES_REPAIRED' if prepared else 'ALREADY_MATCH',
        'changed_files':[path.relative_to(project).as_posix() for path,_ in prepared],
        'database_modified':False,'core_runtime_files_modified':False}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root',type=Path,default=Path.cwd())
    args=parser.parse_args(argv)
    try:print(json.dumps(repair(args.project_root)));return 0
    except Exception as exc:
        result={'status':'LAUNCHER_REPAIR_BLOCKED','error_type':type(exc).__name__}
        if isinstance(exc,ValueError) and str(exc).startswith(('LAUNCHER_OUTSIDE_PROJECT:','LAUNCHER_CONTENT_CHANGED:')):
            result['code']=str(exc)
        for key in ('errno','winerror'):
            if type(getattr(exc,key,None)) is int:result[key]=getattr(exc,key)
        print(json.dumps(result));return 2


if __name__=='__main__':raise SystemExit(main())
