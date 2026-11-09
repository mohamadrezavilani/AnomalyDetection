"""Compare every archived publication against the retained, unstaged algorithm.

Offline SQLite qualification, including raw/capture provenance. This is not a
native PostgreSQL throughput or live Elasticsearch acceptance claim.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB,utc_ns
from p24_foundation.viewer_online import initialize_live,bind_stream,publish_capture,FIVE_NS
from p24_foundation.viewer_runtime import atomic_json,runtime_source_digest
from tools.qualify_viewer_online import projection_digest


def evidence_digest(db):
    result={}
    for table in ('viewer_events','viewer_links','viewer_raw_events',
                  'viewer_event_captures','viewer_capture_projections'):
        cursor=db.sql('SELECT * FROM '+table+' ORDER BY 1,2,3')
        digest=hashlib.sha256();count=0
        while True:
            batch=cursor.fetchmany(500)
            if not batch:break
            for row in batch:
                digest.update(json.dumps(dict(row),sort_keys=True,separators=(',',':'),
                    default=lambda x:bytes(x).hex()).encode()+b'\n');count+=1
        result[table]={'rows':count,'sha256':digest.hexdigest()}
    return result


def qualify(paths):
    windows=[]
    for path in paths:
        with gzip.open(path,'rt',encoding='utf-8') as f: data=json.load(f)
        windows.append((utc_ns(data['window_start']),path))
    windows.sort()
    if not windows or any(b[0]!=a[0]+FIVE_NS for a,b in zip(windows,windows[1:])):
        raise ValueError('consecutive_archived_windows_required')
    report={'mode':'offline_differential_real_archived_windows','status':'RUNNING',
            'runtime_source_sha256':runtime_source_digest(),'windows':[],
            'native_postgresql':'NOT_RUN','owner_throughput':'NOT_RUN'}
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary);keys=root/'keys';generate_keys(keys)
        old=ViewerDB(sqlite_path=root/'old.db',keys_path=keys)
        new=ViewerDB(sqlite_path=root/'new.db',keys_path=keys)
        old._legacy_projection_writes=True
        try:
            for db in (old,new):
                db.init();initialize_live(db)
                bind_stream(db,start_ns=windows[0][0],stream_key='archived_differential')
            jobs=[(start,path,'forward') for start,path in windows]
            jobs.extend((start,path,'recheck') for start,path in (windows[-1],windows[0]))
            for start,path,mode in jobs:
                elapsed=[];writes=[]
                new.progress_callback=lambda event:writes.append(event) if event['stage']=='projection_publish_complete' else None
                for db in (old,new):
                    began=time.monotonic()
                    publish_capture(db,path,start,start+FIVE_NS,mode=mode)
                    elapsed.append(round(time.monotonic()-began,3))
                new.progress_callback=None
                a=projection_digest(old);b=projection_digest(new)
                if a!=b:raise AssertionError('read_model_differential_mismatch')
                a=evidence_digest(old);b=evidence_digest(new)
                if a!=b:raise AssertionError('raw_provenance_differential_mismatch')
                report['windows'].append({'mode':mode,'filename':path.name,'legacy_seconds':elapsed[0],
                    'finalized_seconds':elapsed[1],'all_projections_equal':True,'all_evidence_equal':True,
                    'projection_final_writes':writes})
                print(json.dumps({'window':path.name,'mode':mode,'equal':True}),flush=True)
            report['status']='PASS';report['final_evidence']=b
        finally:old.close();new.close()
    return report


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('paths',type=Path,nargs='+');ap.add_argument('--out',type=Path,required=True)
    args=ap.parse_args();report=qualify(args.paths);atomic_json(args.out,report)
    return 0


if __name__=='__main__':raise SystemExit(main())
