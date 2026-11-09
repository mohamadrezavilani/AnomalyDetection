"""Finite, private SQLite replay of retained source-catalogue migration.

Not a live-ES or native PostgreSQL capacity claim. The Core source is not run.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB,OWNER_CONFIRMED,CANDIDATE_ROLES,SYSTEM_PREFIXES,utc_ns
from p24_foundation.viewer_online import initialize_live,bind_stream,publish_capture,FIVE_NS
from tools.qualify_viewer_online import projection_digest


def old_role(path):
    if path in OWNER_CONFIRMED:return (*OWNER_CONFIRMED[path],'owner_confirmed')
    if path.startswith(SYSTEM_PREFIXES):return ('system','system_followup','inferred')
    if path in CANDIDATE_ROLES:return (CANDIDATE_ROLES[path],'unknown','inferred')
    return ('unknown','unknown','unclassified')


def fingerprints(db):
    result={}
    order={'viewer_events':'origin_key,version_key','viewer_raw_events':'origin_key,version_key',
        'viewer_links':'origin_key,version_key,link_domain,link_key','viewer_event_captures':'file_hash,origin_key,capture_key',
        'viewer_capture_projections':'origin_key,capture_key','viewer_requests':'request_key',
        'viewer_contract_identifiers':'origin_key,version_key,issuer,kind,scope,field_path,identity_key',
        'viewer_contract_edges':'edge_key','viewer_contract_observations':'origin_key,version_key,axis,value,field_path',
        'viewer_live_state':'id','viewer_live_receipts':'receipt_id'}
    def safe_binary(value):
        if isinstance(value,(bytes,memoryview)):return hashlib.sha256(bytes(value)).hexdigest()
        raise TypeError('unsupported_fingerprint_value')
    for table,columns in order.items():
        digest=hashlib.sha256();count=0
        cursor=db.sql('SELECT * FROM '+table+' ORDER BY '+columns)
        while True:
            batch=cursor.fetchmany(500)
            if not batch:break
            for row in batch:
                digest.update(json.dumps(dict(row),sort_keys=True,default=safe_binary,separators=(',',':')).encode());digest.update(b'\n');count+=1
        result[table]=dict(rows=count,sha256=digest.hexdigest())
    return result


def run(paths,out):
    import gzip
    ordered=[]
    for path in paths:
        with gzip.open(path,'rt',encoding='utf-8') as stream:data=json.load(stream)
        ordered.append((utc_ns(data['window_start']),Path(path)))
    ordered.sort()
    if not ordered or any(b[0]!=a[0]+FIVE_NS for a,b in zip(ordered,ordered[1:])):raise ValueError('consecutive_archived_windows_required')
    report=dict(mode='archived_sqlite_retained_catalog_migration',live_elasticsearch='NOT_RUN',
        native_postgresql='NOT_RUN',operational_capacity='NOT_QUALIFIED',production_modified=False)
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp);generate_keys(root/'keys')
        with ViewerDB(sqlite_path=root/'db',keys_path=root/'keys') as db:
            db.init();initialize_live(db);bind_stream(db,start_ns=ordered[0][0],stream_key='archived_source_catalog')
            with patch('p24_foundation.viewer_data.initial_service_role',side_effect=old_role),patch('p24_foundation.service_journey.role_proposal',return_value=None):
                for n,(start,path) in enumerate(ordered):
                    info=publish_capture(db,path,start,start+FIVE_NS)
                    print(json.dumps(dict(window=n,records=info['records'])),flush=True)
            before=db.service_roles(1);before_anchors=db.one("SELECT COUNT(*) AS n FROM viewer_semantic_occurrences WHERE state='active'")['n']
            db.sql("UPDATE viewer_service_catalog_state SET fingerprint='legacy_retained_catalog'");db.conn.commit()
            preserved=fingerprints(db)
            started=time.monotonic()
            with (
                patch.object(db,'rebuild',side_effect=AssertionError('no full request rebuild')),
                patch.object(db,'rebuild_payment_contract',side_effect=AssertionError('no full financial rebuild')),
                patch.object(db,'build_semantic_index',side_effect=AssertionError('no full semantic bootstrap')),
            ):
                migrated=db.sync_service_catalog()
            report['migration_seconds_sqlite']=round(time.monotonic()-started,3)
            report['preserved_raw_requests_contract_and_live_cursor']=preserved==fingerprints(db)
            after=db.service_roles(1);canonical=projection_digest(db)
            history=db.one('SELECT COUNT(*) AS n FROM viewer_service_role_history')['n']
            repeat=db.sync_service_catalog()
            report['repeat_idempotent']=(repeat['status']=='CURRENT' and canonical==projection_digest(db) and history==db.one('SELECT COUNT(*) AS n FROM viewer_service_role_history')['n'])
            db.rebuild();db.rebuild_payment_contract();db.build_semantic_index()
            report['migration_equals_full_batch']=canonical==projection_digest(db)
            report.update(windows=len(ordered),events=preserved['viewer_events']['rows'],requests=preserved['viewer_requests']['rows'],
                before=dict(role_totals=before['role_totals'],active_anchors=before_anchors),
                after=dict(role_totals=after['role_totals'],active_anchors=db.one("SELECT COUNT(*) AS n FROM viewer_semantic_occurrences WHERE state='active'")['n']),
                migration=migrated,preserved_tables=preserved)
            report['status']='PASS' if all(report[key] for key in ('preserved_raw_requests_contract_and_live_cursor','repeat_idempotent','migration_equals_full_batch')) else 'FAIL'
    out=Path(out);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n')
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dumps',type=Path,nargs='+',required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args(argv);report=run(args.dumps,args.out)
    print(json.dumps({key:report[key] for key in ('status','events','requests','migration_seconds_sqlite','preserved_raw_requests_contract_and_live_cursor','repeat_idempotent','migration_equals_full_batch')}))
    return 0 if report['status']=='PASS' else 2


if __name__=='__main__':raise SystemExit(main())
