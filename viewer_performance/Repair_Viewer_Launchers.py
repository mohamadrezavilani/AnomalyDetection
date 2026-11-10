"""Restore verified launcher bytes and their Git index/file-mode metadata.

Can run from Git through stdin before pulling a packaging fix. Never changes
private config, keys, core runtime files or database state. All three inputs
must be byte-identical to the manifest apart from newline representation.
HEAD and the index are checked too; real staged edits are never discarded.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

NAMES=('Start_Viewer.cmd','Start_Viewer_Standard.cmd','tools/viewer.ps1')


def git(project,*arguments):
    result=subprocess.run(['git',*arguments],cwd=project,capture_output=True,timeout=20)
    if result.returncode:raise ValueError('LAUNCHER_GIT_COMMAND_FAILED:'+arguments[0])
    return result.stdout


def newline_content(data):
    return data.replace(b'\r\n',b'\n')


def changed_paths(project,*,cached=False):
    arguments=['diff','--name-only','-z']
    if cached:arguments.append('--cached')
    return set(git(project,*arguments,'--',*NAMES).decode('utf-8').strip('\0').split('\0'))-{''}


def repair(project):
    project=Path(project).resolve()
    manifest=json.loads((project/'RELEASE_MANIFEST.json').read_text(encoding='utf-8-sig'))
    prepared=[];originals={}
    for name in NAMES:
        path=project/name
        if not path.resolve().is_relative_to(project) or path.is_symlink():
            raise ValueError('LAUNCHER_OUTSIDE_PROJECT:'+name)
        original=path.read_bytes();expected=manifest['files_sha256'][name]
        originals[name]=original
        lf=original.replace(b'\r\n',b'\n')
        target=next((data for data in (original,lf,lf.replace(b'\n',b'\r\n'))
            if hashlib.sha256(data).hexdigest()==expected),None)
        if target is None:raise ValueError('LAUNCHER_CONTENT_CHANGED:'+name)
        prepared.append((path,target))
    # A matching manifest does not establish a clean Git checkout. In
    # particular, executable bits or staged CRLF can still block a merge.
    top=git(project,'rev-parse','--show-toplevel').decode('utf-8').strip()
    if Path(top).resolve()!=project:raise ValueError('LAUNCHER_GIT_ROOT_MISMATCH')
    head=git(project,'rev-parse','HEAD').strip()
    for name in NAMES:
        committed=git(project,'show','HEAD:'+name)
        staged=git(project,'show',':'+name)
        entry=git(project,'ls-files','--stage','-z','--',name).split(b'\t',1)[0].split()
        if len(entry)!=3 or entry[0] not in (b'100644',b'100755') or entry[2]!=b'0':
            raise ValueError('LAUNCHER_INDEX_NOT_REGULAR:'+name)
        if newline_content(originals[name])!=newline_content(committed):
            raise ValueError('LAUNCHER_HEAD_CONTENT_CHANGED:'+name)
        if newline_content(staged)!=newline_content(committed):
            raise ValueError('LAUNCHER_INDEX_CONTENT_CHANGED:'+name)
    git_changes=changed_paths(project)|changed_paths(project,cached=True)
    byte_changes={path.relative_to(project).as_posix() for path,target in prepared
        if originals[path.relative_to(project).as_posix()]!=target}
    if git(project,'rev-parse','HEAD').strip()!=head or any(
            (project/name).read_bytes()!=originals[name] for name in NAMES):
        raise ValueError('LAUNCHER_STATE_CHANGED_DURING_REPAIR')
    # Restore only these three paths, including the index. All working and
    # staged contents were verified against HEAD before this mutation.
    git(project,'restore','--source=HEAD','--staged','--worktree','--',*NAMES)
    # Validate every file before writing any. Each replacement is atomic;
    # rerunning is safe even if one later replacement hits a filesystem error.
    for path,target in prepared:
        if path.read_bytes()==target:continue
        temporary=None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent,prefix=path.name+'.',suffix='.tmp',delete=False) as stream:
                temporary=Path(stream.name);stream.write(target);stream.flush();os.fsync(stream.fileno())
            temporary.chmod(path.stat().st_mode & 0o777)
            temporary.replace(path)
        finally:
            if temporary is not None:temporary.unlink(missing_ok=True)
    mode_tracking_disabled=False
    # Windows cannot represent Git's Unix executable bits reliably. If the
    # only remaining launcher difference is a mode bit, disable that check
    # locally for this Windows checkout. Content checks remain mandatory.
    if os.name=='nt' and changed_paths(project):
        content_diff=git(project,'-c','core.filemode=false','diff','--name-only','-z','--',*NAMES)
        if not content_diff:
            git(project,'config','--local','core.filemode','false');mode_tracking_disabled=True
    if changed_paths(project) or changed_paths(project,cached=True):
        raise ValueError('LAUNCHER_GIT_STATE_NOT_CLEAN')
    if any(hashlib.sha256((project/name).read_bytes()).hexdigest()!=manifest['files_sha256'][name]
            for name in NAMES):raise ValueError('LAUNCHER_HASH_CHECK_FAILED')
    changed=git_changes|byte_changes
    return {'status':'EXACT_LAUNCHER_BYTES_REPAIRED' if changed else 'ALREADY_MATCH',
        'changed_files':sorted(changed),'git_launchers_clean':True,
        'windows_filemode_tracking_disabled':mode_tracking_disabled,
        'database_modified':False,'core_runtime_files_modified':False}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root',type=Path,default=Path.cwd())
    args=parser.parse_args(argv)
    try:print(json.dumps(repair(args.project_root)));return 0
    except Exception as exc:
        result={'status':'LAUNCHER_REPAIR_BLOCKED','error_type':type(exc).__name__}
        if isinstance(exc,ValueError) and str(exc).startswith('LAUNCHER_'):
            result['code']=str(exc)
        for key in ('errno','winerror'):
            if type(getattr(exc,key,None)) is int:result[key]=getattr(exc,key)
        print(json.dumps(result));return 2


if __name__=='__main__':raise SystemExit(main())
