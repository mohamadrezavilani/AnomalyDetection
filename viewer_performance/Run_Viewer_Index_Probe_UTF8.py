"""Run the pinned read-only index observer with UTF-8 process transport."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

CAPACITY_SHA='8abbdc17d427e9d2c2472d8a9efd50dabce2fa5de6dd8a93e12aabc29bdea6ff'
RUNTIME_SHA='b7273437ea42c1aea7d0183c3020be133c84dba5735c68a01a6fd81a4b56d7c8'
SHARED='viewer_performance/Observe_Viewer_Index_Parallel.py'
DEPENDENCIES=(SHARED,'viewer_performance/Observe_Viewer_Index_Cost.py',
    'viewer_performance/Qualify_Capacity_Candidate.py',
    *(f'viewer_performance/capacity/{name}.py' for name in
      ('index_prefetch','local_projection_keys','contract_fetch_once','origin_filter','trace')))


def utf8_environment():
    return dict(os.environ,PYTHONUTF8='1',PYTHONIOENCODING='utf-8:strict')


def run_utf8(command,*,timeout):
    return subprocess.run(command,env=utf8_environment(),capture_output=True,
        encoding='utf-8',errors='strict',timeout=timeout)


def verify_sources(project):
    body=(project/'viewer_performance/CAPACITY_MANIFEST.json').read_bytes()
    if hashlib.sha256(body).hexdigest()!=CAPACITY_SHA:
        raise ValueError('shared_capacity_manifest_mismatch')
    entries=json.loads(body)['files_sha256']
    for name in DEPENDENCIES:
        path=(project/name).resolve()
        if not path.is_relative_to(project) or hashlib.sha256(path.read_bytes()).hexdigest()!=entries[name]:
            raise ValueError('shared_observer_source_mismatch')
    return entries[SHARED]


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--seconds',type=int,default=30)
    args=parser.parse_args(argv);project=args.project.resolve()
    try:
        if not 10<=args.seconds<=60:raise ValueError('parallel_probe_budget_must_be_10_to_60_seconds')
        shared_sha=verify_sources(project)
        if not (sys.flags.utf8_mode==1 and os.environ.get('PYTHONIOENCODING')=='utf-8:strict'):
            # A fresh interpreter is necessary: setting PYTHONUTF8 after Python
            # startup does not change subprocess's default text decoder.
            child=run_utf8([sys.executable,'-B',str(Path(__file__).resolve()),
                '--project',str(project),'--seconds',str(args.seconds)],timeout=args.seconds+35)
            if child.stdout:sys.stdout.write(child.stdout)
            elif child.returncode:
                print(json.dumps(dict(status='READ_ONLY_PARALLEL_INDEX_BLOCKED',
                    code='utf8_observer_child_failed',exit_code=child.returncode,
                    database_modified=False,workers_restarted=False)))
            return child.returncode
        sys.path.insert(0,str(project))
        from viewer_performance import Observe_Viewer_Index_Parallel as shared
        from viewer_performance.Qualify_Capacity_Candidate import literal_database
        from p24_foundation.viewer_runtime import runtime_source_digest,atomic_json
        if Path(shared.__file__).resolve()!=(project/SHARED).resolve():
            raise ValueError('shared_observer_import_mismatch')
        if runtime_source_digest(project)!=RUNTIME_SHA:
            raise ValueError('installed_viewer_is_not_the_recorded_baseline')
        result=shared.observe(literal_database(project),lambda:shared.ad_status(project),seconds=args.seconds)
        result.update(runtime_source_sha256=RUNTIME_SHA,probe_source_sha256=shared_sha,
            runtime_still_matches=runtime_source_digest(project)==RUNTIME_SHA,
            transport=dict(launcher_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                capacity_manifest_sha256=CAPACITY_SHA,python_utf8_mode=sys.flags.utf8_mode,
                stdio_encoding='utf-8:strict',calling_environment_modified=False,
                worker_environment_modified=False))
        if not result['runtime_still_matches']:result['status']='PARTIAL_READ_ONLY_PARALLEL_INDEX_OBSERVATION'
        output=project/'AnomalyDetection/reports'/('Viewer_Index_Parallel_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8]+'.json')
        atomic_json(output,result)
        notice={k:result[k] for k in ('status','complete_cells','workers_observed_alive_and_unchanged','database_modified','workers_restarted')}
        notice['output']=str(output)
    except Exception as exc:
        notice=dict(status='READ_ONLY_PARALLEL_INDEX_BLOCKED',error_type=type(exc).__name__,
            code=str(exc) if isinstance(exc,ValueError) else None,
            sqlstate=getattr(exc,'sqlstate',None),database_modified=False,workers_restarted=False)
    # ASCII JSON also survives an outer redirected console with an ANSI codec.
    print(json.dumps(notice,ensure_ascii=True))
    return 2 if notice['status']=='READ_ONLY_PARALLEL_INDEX_BLOCKED' else 0


if __name__=='__main__':raise SystemExit(main())
