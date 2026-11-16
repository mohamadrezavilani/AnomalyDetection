"""Compare a candidate on the owner host using private verified Captures.

Reads literal local connection settings without executing the config. Connects
only to postgres and databases allocated by this invocation; never to the
Viewer product database. No worker, cursor, source or global setting changes.
"""
import argparse
import ast
from contextlib import contextmanager
from datetime import datetime,timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import uuid
import zipfile

EXPECTED_RUNTIME='b7273437ea42c1aea7d0183c3020be133c84dba5735c68a01a6fd81a4b56d7c8'
MIB=1024**2


def literal_database(project):
    path=project/'viewer_config.local.py'
    if not path.is_file():raise ValueError('literal_database_config_required')
    values=[]
    for node in ast.parse(path.read_text(encoding='utf-8-sig')).body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='DATABASE' for t in node.targets):
            try:values.append(ast.literal_eval(node.value))
            except (ValueError,TypeError):raise ValueError('literal_database_config_required') from None
    if len(values)!=1 or not isinstance(values[0],dict):raise ValueError('literal_database_config_required')
    config=values[0]
    if str(config.get('host','127.0.0.1')).lower() not in ('localhost','127.0.0.1','::1'):
        raise ValueError('local_qualification_server_required')
    if config.get('dbname')!='p24_design_viewer':raise ValueError('recorded_viewer_config_required')
    if not isinstance(config.get('user'),str):raise ValueError('database_user_required')
    return config


def extract_captures(bundle,target):
    if bundle.stat().st_size>97*MIB:raise ValueError('capture_bundle_byte_budget_exceeded')
    with zipfile.ZipFile(bundle) as archive:
        entries=archive.infolist()
        if len(entries)!=5 or len({x.filename for x in entries})!=5:
            raise ValueError('exact_four_capture_bundle_required')
        for entry in entries:
            if '/' in entry.filename or '\\' in entry.filename or entry.filename in ('.','..'):
                raise ValueError('invalid_capture_bundle_path')
        manifest=json.loads(archive.read('manifest.json'))
        captures=manifest.get('captures',[])
        if manifest.get('runtime_source_sha256')!=EXPECTED_RUNTIME or len(captures)!=4:
            raise ValueError('capture_bundle_baseline_mismatch')
        names=[c.get('archive_name') for c in captures]
        if len(set(names))!=4 or set(names)|{'manifest.json'}!={x.filename for x in entries}:
            raise ValueError('capture_bundle_members_mismatch')
        paths=[]
        if sum(x.file_size for x in entries)>97*MIB:raise ValueError('capture_bundle_byte_budget_exceeded')
        for item in captures:
            name=item['archive_name'];info=archive.getinfo(name)
            if not name.endswith('.gz') or info.file_size>32*MIB:
                raise ValueError('capture_file_budget_exceeded')
            content=archive.read(name)
            if hashlib.sha256(content).hexdigest()!=item['sha256']:
                raise ValueError('capture_bundle_digest_mismatch')
            path=target/name;path.write_bytes(content);del content
            with gzip.open(path,'rb') as stream:expanded=stream.read(192*MIB+1)
            if len(expanded)>192*MIB:raise ValueError('expanded_capture_budget_exceeded')
            del expanded;paths.append(path)
    return paths


@contextmanager
def connection_environment(config):
    settings={'P24_DELTA_PG_HOST':str(config.get('host','127.0.0.1')),
        'P24_DELTA_PG_PORT':str(int(config.get('port',5432))),
        'P24_DELTA_PG_USER':config['user']}
    if config.get('password') is not None:settings['PGPASSWORD']=str(config['password'])
    previous={key:os.environ.get(key) for key in settings}
    try:
        os.environ.update(settings);yield
    finally:
        for key,value in previous.items():
            if value is None:os.environ.pop(key,None)
            else:os.environ[key]=value


def qualify(project,bundle,*,pairs=2,experiment='contract_fetch_once',notice=None):
    project=project.resolve();bundle=bundle.resolve();sys.path.insert(0,str(project))
    from p24_foundation.viewer_runtime import runtime_source_digest,atomic_json
    from viewer_performance.capacity import baseline
    if runtime_source_digest(project)!=EXPECTED_RUNTIME:
        raise ValueError('installed_viewer_is_not_the_recorded_baseline')
    config=literal_database(project)
    code_root=Path(__file__).resolve().parent
    def qualification_hashes():
        files=[Path(__file__).resolve(),*sorted((code_root/'capacity').glob('*.py'))]
        return {path.relative_to(code_root).as_posix():hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    code_before=qualification_hashes()
    if not 1<=pairs<=2:raise ValueError('owner_qualification_pairs_must_be_1_to_2')
    output=project/'AnomalyDetection/reports'/('Viewer_Capacity_Candidate_'+
        datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8]+'.json')
    with tempfile.TemporaryDirectory(prefix='p24-private-capacity-') as folder:
        captures=extract_captures(bundle,Path(folder))
        with connection_environment(config):
            result=baseline.run(backend='postgresql',pairs=pairs,captures=captures,
                experiment=experiment,wal_compression='zstd',notice=notice)
    result.update(product_database_opened=False,product_database_modified=False,
        workers_restarted=False,source_config_executed=False,
        shared_host_load_is_not_controlled=True,
        owner_host_capacity='NOT_ACCEPTED_FOUR_CAPTURE_CALIBRATION',
        qualification_files_sha256=code_before,
        qualification_files_unchanged_during_run=qualification_hashes()==code_before,
        runtime_still_matches=runtime_source_digest(project)==EXPECTED_RUNTIME,
        input_bundle_sha256=hashlib.sha256(bundle.read_bytes()).hexdigest())
    if not result['qualification_files_unchanged_during_run']:
        result['status']='FAILED_QUALIFICATION_FILES_CHANGED'
    if not result['runtime_still_matches']:result['status']='FAILED_RUNTIME_CHANGED_DURING_QUALIFICATION'
    atomic_json(output,result)
    return dict(status=result['status'],output=str(output),failure=result.get('failure'),
        product_database_opened=False,product_database_modified=False,workers_restarted=False,
        qualification_databases_only=True,
        comparisons=result.get('candidate_comparisons_including_build'))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--captures-zip',type=Path,required=True)
    parser.add_argument('--pairs',type=int,choices=(1,2),default=2)
    parser.add_argument('--experiment',choices=('origin_filter','contract_fetch_once','local_projection_keys'),default='contract_fetch_once')
    args=parser.parse_args(argv)
    done=threading.Event();began=time.monotonic()
    def notice(value):print(json.dumps(value),flush=True)
    def heartbeat():
        while not done.wait(15):
            notice(dict(status='CAPACITY_QUALIFICATION_RUNNING',elapsed_seconds=round(time.monotonic()-began,1)))
    thread=threading.Thread(target=heartbeat,daemon=True);thread.start()
    try:result=qualify(args.project,args.captures_zip,pairs=args.pairs,experiment=args.experiment,notice=notice)
    except Exception as exc:
        result=dict(status='CAPACITY_QUALIFICATION_BLOCKED',error_type=type(exc).__name__,
            code=str(exc) if isinstance(exc,ValueError) else None,
            product_database_opened=False,product_database_modified=False,workers_restarted=False)
    finally:done.set();thread.join(1)
    print(json.dumps(result))
    return 0 if result['status']=='PASS_CANDIDATE_EQUIVALENCE' else 2


if __name__=='__main__':raise SystemExit(main())
