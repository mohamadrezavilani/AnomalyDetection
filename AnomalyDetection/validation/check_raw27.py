"""Exercise retained-row selection and physical reclamation on disposable PostgreSQL."""
import argparse
from datetime import datetime,timedelta
import json
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.history_reset import tehran_boundary
from anomaly_detection.history_scope import STATE_KEY
from anomaly_detection.snapshot import ContractError
from anomaly_detection.temporal import TIMEZONE
from anomaly_detection.viewer_raw_retention import compact,scope_status,state,RECEIPT_KEY


def seed(raw, cutoff):
    for sql in (
        'CREATE SCHEMA anomaly_detection',
        'CREATE TABLE anomaly_detection.adp_state(name text PRIMARY KEY,body text NOT NULL)',
        'CREATE TABLE anomaly_detection.adp_models(key text PRIMARY KEY,body text)',
        "INSERT INTO anomaly_detection.adp_models VALUES('baseline','baseline-kept')",
        'CREATE TABLE public.viewer_events(origin_key text,version_key text,at_ns bigint,'
        'request_key text,callpath text NOT NULL,PRIMARY KEY(origin_key,version_key))',
        'CREATE INDEX ON public.viewer_events(request_key,at_ns)',
        'CREATE INDEX ON public.viewer_events(at_ns)',
        'CREATE TABLE public.viewer_requests(request_key text PRIMARY KEY,started_ns bigint,ended_ns bigint,root_ns bigint)',
        'CREATE TABLE public.viewer_raw_events(origin_key text,version_key text,raw_request_id text,'
        'raw_session_id text,raw_ip text,payload bytea NOT NULL,PRIMARY KEY(origin_key,version_key))',
        'CREATE TABLE public.viewer_capture_projections(origin_key text,capture_key text,canonical_version_key text,'
        'file_hash text,filename text,row_number integer,payload bytea NOT NULL,PRIMARY KEY(origin_key,capture_key))',
        'CREATE TABLE public.viewer_live_state(id integer PRIMARY KEY,next_ns bigint,generation bigint,'
        'stream_key text,keys_fingerprint text,last_error text,overlap_windows integer,lag_seconds integer)',
        'CREATE TABLE public.viewer_semantic_checkpoint(id integer PRIMARY KEY,state text,generation bigint)',
        'CREATE TABLE public.viewer_live_windows(start_ns bigint PRIMARY KEY,end_ns bigint)',
        'CREATE TABLE public.viewer_contract_edges(id text PRIMARY KEY,value text NOT NULL)',
        "INSERT INTO public.viewer_contract_edges VALUES('typed','preserved')",
    ):
        raw.execute(sql)
    raw.execute("INSERT INTO public.viewer_live_state VALUES(1,%s,3,'test','key',NULL,2,60)",(cutoff+5*FIVE_NS,))
    raw.execute("INSERT INTO public.viewer_semantic_checkpoint VALUES(1,'ready',3)")
    raw.execute('INSERT INTO anomaly_detection.adp_state VALUES(%s,%s),(%s,%s)',
                (STATE_KEY,json.dumps({'start_ns':cutoff}),'source_binding',
                 json.dumps({'namespace':'viewer:test','keys_fingerprint':'key'})))
    raw.execute("INSERT INTO public.viewer_requests VALUES('across',%s,%s,%s)",
                (cutoff-1,cutoff+1,cutoff-1))
    raw.execute("INSERT INTO public.viewer_events VALUES ('today','v',%s,'new','App.Read'),"
                "('across','v',%s,'across','App.Read'),('typed','v',%s,'p','App.Payment'),"
                "('undated','v',NULL,NULL,'App.Read'),('today','other',%s,'new','App.Read')",
                (cutoff,cutoff-1,cutoff-100,cutoff-1))
    raw.execute("INSERT INTO public.viewer_events SELECT 'old'||i,'v',%s,NULL,'App.Read' "
                'FROM generate_series(1,5000) i',(cutoff-100,))
    raw.execute("INSERT INTO public.viewer_raw_events SELECT origin_key,version_key,NULL,NULL,NULL,"
                "convert_to(repeat(md5(origin_key),128),'UTF8') FROM public.viewer_events")
    raw.execute("INSERT INTO public.viewer_raw_events VALUES('orphan','v',NULL,NULL,NULL,decode('AB','hex'))")
    raw.execute("INSERT INTO public.viewer_capture_projections SELECT origin_key,'c'||version_key,version_key,"
                "'file','file',1,payload FROM public.viewer_raw_events")


def check(raw, pgdata, cutoff):
    checks={}
    seed(raw,cutoff)
    def apply(**kw):
        return compact(raw,Path(__file__).resolve().parents[1],cutoff,('%Payment%',),
                       pg_data_dir=pgdata,**kw)
    assert scope_status(raw,cutoff)['latest_published_window_end_ns'] is None
    raw.execute('INSERT INTO public.viewer_live_windows VALUES(%s,%s)',(cutoff,cutoff+FIVE_NS))
    assert scope_status(raw,cutoff)['latest_published_window_end_ns']==cutoff+FIVE_NS
    checks['seek_cursor_alone_does_not_prove_publication']='PASS'
    before=[raw.execute(f'SELECT * FROM {table} ORDER BY 1').fetchall() for table in
            ('public.viewer_events','public.viewer_requests','public.viewer_contract_edges','anomaly_detection.adp_models')]
    def fault():
        raise RuntimeError('injected')
    try:
        apply(fault=fault)
    except RuntimeError as exc:
        assert str(exc)=='injected'
    else:
        raise AssertionError('rollback fault missed')
    assert raw.execute('SELECT count(*) AS n FROM public.viewer_raw_events').fetchone()['n']==5006
    assert not state(raw,RECEIPT_KEY)
    checks['fault_after_truncate_restores_both_tables_and_no_receipt']='PASS'
    raw.execute('CREATE TABLE public.dependency(origin text,version text,FOREIGN KEY(origin,version) '
                'REFERENCES public.viewer_raw_events(origin_key,version_key))')
    try:
        apply()
    except ContractError as exc:
        assert str(exc)=='HISTORY_RESET_UNEXPECTED_TABLE_DEPENDENCY'
    else:
        raise AssertionError('unexpected FK accepted')
    raw.execute('DROP TABLE public.dependency')
    checks['rejects_foreign_dependency_before_deletion']='PASS'
    kept=['across','orphan','today','today','typed','undated']
    original=[raw.execute(f'SELECT * FROM public.{table} WHERE origin_key=ANY(%s) ORDER BY 1,2',
                         (kept,)).fetchall() for table in ('viewer_raw_events','viewer_capture_projections')]
    result=apply()
    assert result['status']=='VIEWER_RAW_APPLIED', result
    assert result['raw_relation_bytes_reclaimed']>1024**2, result
    after=[raw.execute(f'SELECT * FROM public.{table} ORDER BY 1,2').fetchall()
           for table in ('viewer_raw_events','viewer_capture_projections')]
    assert after==original and [r['origin_key'] for r in after[0]]==kept
    assert all(v['rows']-v['kept_rows']==5000 for v in result['counts'].values())
    assert before==[raw.execute(f'SELECT * FROM {table} ORDER BY 1').fetchall() for table in
                    ('public.viewer_events','public.viewer_requests','public.viewer_contract_edges','anomaly_detection.adp_models')]
    assert scope_status(raw,cutoff)==result['scope']
    checks['old_payloads_only_and_exact_bytes_preserved_for_required_rows']='PASS'
    checks['request_event_payment_baseline_checkpoint_preserved']='PASS'
    checks['physical_relation_bytes_reclaimed']=result['raw_relation_bytes_reclaimed']
    assert apply()['status']=='VIEWER_RAW_ALREADY_APPLIED'
    checks['atomic_receipt_and_idempotent_retry']='PASS'
    return checks


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--port',type=int,required=True)
    ap.add_argument('--pg-data-dir',type=Path,required=True)
    args=ap.parse_args()
    params={'host':'127.0.0.1','port':args.port,'dbname':'postgres','user':'postgres',
            'autocommit':True,'row_factory':dict_row}
    day=(datetime.now(TIMEZONE).date()-timedelta(days=1)).isoformat()
    _,cutoff=tehran_boundary(day)
    with psycopg.connect(**params) as admin:
        version=admin.execute('SHOW server_version').fetchone()['server_version']
        admin.execute('CREATE DATABASE p24_design_viewer')
    with psycopg.connect(**dict(params,dbname='p24_design_viewer')) as raw:
        checks=check(raw,args.pg_data_dir,cutoff)
    print(json.dumps({'status':'PASS_RAW_RETENTION_POSTGRESQL_FIXTURE','build_id':BUILD_ID,
                      'postgresql':version,'owner_windows':'NOT_RUN','checks':checks},indent=2))


if __name__=='__main__':
    main()
