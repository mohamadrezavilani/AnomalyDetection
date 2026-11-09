"""Hash-guarded file update support for the isolated Batch 2H test package."""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid


class PatchError(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def target_file(root, relative):
    path=Path(relative)
    if path.is_absolute() or not path.parts or any(part in {'..','.'} for part in path.parts):
        raise PatchError('Invalid update path.')
    result=root/path
    if any(p.is_symlink() for p in [result,*result.parents] if p!=root.parent):
        raise PatchError('Symbolic links are not supported by this test update.')
    if not result.resolve().is_relative_to(root.resolve()):
        raise PatchError('Update path is outside the test package.')
    return result


def validate_test_target(root):
    for relative in ['p24_foundation/config.py','tools/run_tests.py','db_config.local.py']:
        if not (root/relative).is_file():
            raise PatchError('Target must be your extracted and configured Batch 2H test folder.')
    try:
        tree=ast.parse((root/'db_config.local.py').read_text(encoding='utf-8-sig'))
        values=[ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign)
                and any(isinstance(t,ast.Name) and t.id=='DATABASE' for t in n.targets)]
        database=values[0] if len(values)==1 else {}
        if (database.get('host') not in {'127.0.0.1','::1','localhost'}
                or not re.fullmatch(r'p24_design_[a-z0-9_]{1,48}',str(database.get('dbname','')))):
            raise ValueError
    except Exception:
        raise PatchError('Local configuration must target a loopback p24_design_* test database.') from None


def atomic_write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.batch2h-update-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        Path(name).unlink(missing_ok=True)


def install_files(root,files):
    root=Path(root).resolve();changes=[]
    for item in files:
        path=target_file(root,item['path']);new=item['content'].encode('utf-8')
        if digest(new)!=item['new_sha256']:
            raise PatchError('Damaged update payload: '+item['path'])
        if path.exists() and not path.is_file():
            raise PatchError('Expected a regular file: '+item['path'])
        old=path.read_bytes() if path.exists() else None
        old_hash=digest(old) if old is not None else None
        if old_hash==item['new_sha256']:
            continue
        if old_hash!=item['old_sha256']:
            raise PatchError('Local file differs from the reviewed candidate: '+item['path']+'. No files replaced.')
        if path.suffix=='.py':compile(new,item['path'],'exec')
        changes.append((item,path,old,new))
    if not changes:
        return None
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:10]
    backup=root/'private/patch_backups'/('batch2h_2h2_'+stamp)
    backup.mkdir(parents=True,mode=0o700)
    ledger=[]
    for item,path,old,new in changes:
        if old is not None:atomic_write(backup/item['path'],old)
        ledger.append(dict(path=item['path'],old_sha256=item['old_sha256'],new_sha256=item['new_sha256'],existed=old is not None))
    atomic_write(backup/'changed_files.json',(json.dumps(ledger,indent=2)+'\n').encode())
    applied=[]
    try:
        for item,path,old,new in changes:
            atomic_write(path,new);applied.append((path,old))
            if digest(path.read_bytes())!=item['new_sha256']:
                raise PatchError('File verification failed: '+item['path'])
    except Exception:
        failed=[]
        for path,old in reversed(applied):
            try:
                if old is None:path.unlink(missing_ok=True)
                else:atomic_write(path,old)
            except Exception:failed.append(path.name)
        if failed:raise PatchError('Update failed; manual restore needed from '+str(backup)) from None
        raise PatchError('Update failed; changed files were restored. Backup: '+str(backup)) from None
    return backup


def main(payload,argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target',type=Path,required=True)
    args=parser.parse_args(argv);root=args.target.resolve()
    try:
        validate_test_target(root)
        print('Batch 2H repair p24-foundation.2h.2: '+str(root),flush=True)
        print('Files covered by this update:',flush=True)
        for item in payload['files']:print('  '+item['path'],flush=True)
        backup=install_files(root,payload['files'])
        print('Source checks passed. '+('Backup: '+str(backup) if backup else 'Files already match this update.'),flush=True)
        folder=root/'validation';folder.mkdir(exist_ok=True)
        report=folder/'batch_2h_2_postgres.json';console=folder/'batch_2h_2_console.txt'
        if report.exists():
            history=folder/'previous_results';history.mkdir(exist_ok=True)
            os.replace(report,history/('batch_2h_2_postgres_'+uuid.uuid4().hex+'.json'))
        command=[sys.executable,'-u',str(root/'tools/run_tests.py'),'--config',str(root/'db_config.local.py'),'--output',str(report)]
        env=os.environ.copy();env['PYTHONIOENCODING']='utf-8'
        print('Running the full suite against your configured disposable test database.',flush=True)
        with console.open('w',encoding='utf-8') as output:
            process=subprocess.Popen(command,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                text=True,encoding='utf-8',errors='replace',env=env)
            try:
                for line in process.stdout:
                    output.write(line);output.flush();print(line,end='',flush=True)
                code=process.wait()
            except KeyboardInterrupt:
                process.terminate();process.wait();raise
        print('\nTest exit code: '+str(code),flush=True)
        print('Send: '+str(console),flush=True)
        print('Send if created: '+str(report),flush=True)
        return code
    except PatchError as error:
        print(str(error));return 1
    except KeyboardInterrupt:
        print('Test execution interrupted. Applied files and captured output remain available.');return 1
    except Exception as error:
        print('Update could not complete ('+type(error).__name__+'). Check folder permissions and the Python environment.');return 1
