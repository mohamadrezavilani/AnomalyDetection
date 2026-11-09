"""D1 isolated archived replay without browser; never native PostgreSQL acceptance.

Defaults to a fresh temporary SQLite Viewer. --config must name an EMPTY
p24_design_*_qualification PostgreSQL database; no reset/drop is performed.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from p24_foundation.viewer_data import ViewerDB,utc_ns
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_online import initialize_live,bind_stream,publish_capture,FIVE_NS,validate_capture
from p24_foundation.viewer_runtime import runtime_source_digest


def projection_digest(db):
    columns={
      'viewer_requests':'*','viewer_actions':'*','viewer_action_history':'*',
      'viewer_contract_identifiers':'*','viewer_contract_edges':'*','viewer_contract_observations':'*',
      'viewer_semantic_occurrences':'request_key,anchor_key,session_key,anchor_ns,kind,occurrence_key,root_call,root_code,category,initiation,state',
      'viewer_semantic_session_heads':'*',
    }
    out={}
    for table,cols in columns.items():
        cur=db.sql('SELECT '+cols+' FROM '+table+' ORDER BY '+{
            'viewer_requests':'request_key','viewer_actions':'action_key',
            'viewer_action_history':'action_key,origin_key,version_key,status',
            'viewer_contract_identifiers':'origin_key,version_key,issuer,kind,scope,field_path,identity_key',
            'viewer_contract_edges':'edge_key','viewer_contract_observations':'origin_key,version_key,axis,value,field_path',
            'viewer_semantic_occurrences':'request_key','viewer_semantic_session_heads':'session_key'}[table])
        count=0;digest=hashlib.sha256()
        while True:
            batch=cur.fetchmany(500)
            if not batch:break
            for r in batch:
                digest.update(json.dumps(dict(r),sort_keys=True,ensure_ascii=True,separators=(',',':')).encode())
                digest.update(b'\n');count+=1
        out[table]=dict(rows=count,sha256=digest.hexdigest())
    return out


def run(paths,out,*,database=None):
    report=dict(source_sha256=runtime_source_digest(),mode='D1_archived_real_windows_SQLite',live_elasticsearch='NOT_RUN',
       owner_windows_native_postgresql='NOT_RUN',operational_capacity='NOT_QUALIFIED',
       full_r5_acceptance=0,production_modified=False,windows=[])
    first=[]
    for p in paths:
        with gzip.open(p,'rt',encoding='utf-8') as f:data=json.load(f)
        first.append((utc_ns(data['window_start']),p));del data
    first.sort()
    if not first:raise ValueError('no_archived_windows')
    if any(b[0]!=a[0]+FIVE_NS for a,b in zip(first,first[1:])):
        raise ValueError('archived_windows_must_be_consecutive')
    with tempfile.TemporaryDirectory(prefix='p24_viewer_qualification_') as t:
        root=Path(t);keys=root/'keys.json';generate_keys(keys)
        opts=dict(keys_path=keys)
        if database:
            if not str(database.get('dbname','')).startswith('p24_design_') or not str(database['dbname']).endswith('_qualification'):
                raise ValueError('use_empty_p24_design_qualification_database')
            opts['config']=database
        else:opts['sqlite_path']=root/'viewer.sqlite3'
        db=ViewerDB(**opts)
        try:
            db.init();initialize_live(db)
            if db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'] or db.one('SELECT COUNT(*) AS n FROM viewer_live_state')['n']:
                raise ValueError('qualification_database_not_empty')
            bind_stream(db,start_ns=first[0][0],stream_key='archived_qualification')
            cpu_start=time.process_time();began=time.monotonic()
            for i,(start,p) in enumerate(first):
                if i==2:
                    before=projection_digest(db)
                    def crash(point):
                        if point=='before_commit':raise RuntimeError('controlled_restart')
                    try:publish_capture(db,p,start,start+FIVE_NS,fault=crash)
                    except RuntimeError:pass
                    if before!=projection_digest(db):raise ValueError('rollback_did_not_preserve_previous_generation')
                    db.close();db=ViewerDB(**opts)
                    report['pre_commit_restart_preserved']=True
                info=publish_capture(db,p,start,start+FIVE_NS)
                report['windows'].append(dict(ordinal=i,**info))
                print(json.dumps(dict(window=i,records=info['records'],seconds=info['elapsed_seconds'])),flush=True)
            canonical=projection_digest(db)
            raw_before=db.one('SELECT COUNT(*) AS n FROM viewer_events')['n']
            for start,p in (first[0],first[-1]):publish_capture(db,p,start,start+FIVE_NS,mode='recheck')
            report['duplicate_recheck_idempotent']=(canonical==projection_digest(db) and raw_before==db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'])
            db.rebuild();db.rebuild_payment_contract();db.build_semantic_index()
            report['incremental_equals_full_batch']=canonical==projection_digest(db)
            report['derived_tables']=canonical
            report['counts']=db.metrics()
            report['semantic_anchors']=db.one("SELECT COUNT(*) AS n FROM viewer_semantic_occurrences WHERE state='active'")['n']
            report['elapsed_seconds']=round(time.monotonic()-began,3)
            report['cpu_seconds']=round(time.process_time()-cpu_start,3)
            try:
                import resource
                report['process_peak_rss_kib']=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            except ImportError:report['process_peak_rss_kib']='NOT_MEASURED'
            report['status']='PASS' if report['duplicate_recheck_idempotent'] and report['incremental_equals_full_batch'] else 'FAIL'
        finally:db.close()
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return report


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--dumps',type=Path,nargs='+',required=True)
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--config',type=Path)
    args=ap.parse_args(argv)
    database=None
    if args.config:
        spec=importlib.util.spec_from_file_location('qualification_config',args.config.resolve())
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);database=module.DATABASE
    try:report=run(args.dumps,args.out,database=database)
    except Exception as exc:
        print(json.dumps(dict(status='FAILED',error=type(exc).__name__)),file=sys.stderr)
        return 2
    print(json.dumps({k:report[k] for k in ('status','incremental_equals_full_batch','duplicate_recheck_idempotent')}))
    return 0 if report['status']=='PASS' else 2

if __name__=='__main__':raise SystemExit(main())
