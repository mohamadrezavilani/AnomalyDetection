"""Bounded, read-only post-timeout D0 diagnostic for the existing Viewer DB.

No EXPLAIN ANALYZE, ingestion, replay, table mutation, state reset or key export.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import importlib.util
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from p24_foundation.viewer_data import ViewerDB,OWNER_CONFIRMED,utc_ns
from p24_foundation.viewer_runtime import atomic_json,runtime_source_digest

FAILED_START_NS=utc_ns('2026-10-27T05:20:00Z')

def diagnose(config):
    spec=importlib.util.spec_from_file_location('viewer_private_diagnostic',str(config))
    cfg=importlib.util.module_from_spec(spec);spec.loader.exec_module(cfg)
    db_config=dict(cfg.DATABASE)
    # Do not allow this diagnostic to target any other database silently.
    if db_config.get('dbname')!='p24_design_viewer':
        raise ValueError('D0_REQUIRES_EXACT_p24_design_viewer')
    db_config.setdefault('connect_timeout',8)
    with ViewerDB(config=db_config,keys_path=Path(cfg.KEYS_PATH).expanduser()) as db:
        db.sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        db.sql('SET LOCAL statement_timeout=8000')
        result=dict(status='D0_OBSERVED',mode='read_only_post_failure_snapshot',
                    database='p24_design_viewer',no_ingest_or_checkpoint_change=True,
                    runtime_source_sha256=runtime_source_digest(),
                    checked_at_utc=datetime.now(timezone.utc).isoformat(),
                    server_version=db.one('SELECT current_setting(\'server_version\') AS v')['v'])
        state=db.one('''SELECT generation, next_ns,worker_status,last_publish_ns,last_success_ns,
                               last_error,overlap_windows,lag_seconds FROM viewer_live_state WHERE id=1''')
        if state is None:raise ValueError('LIVE_STATE_MISSING')
        result['checkpoint']=dict(generation=state['generation'],next_ns=state['next_ns'],
            next_utc=datetime.fromtimestamp(state['next_ns']/1e9,timezone.utc).isoformat(),
            worker_status=state['worker_status'],has_error=bool(state['last_error']),
            overlap_windows=state['overlap_windows'],lag_seconds=state['lag_seconds'])
        expected=state['next_ns'] == FAILED_START_NS
        published=db.one('''SELECT COUNT(*) AS windows,MAX(generation) AS generation
                 FROM viewer_live_windows WHERE start_ns=?''',(FAILED_START_NS,))
        receipts=db.one('''SELECT COUNT(*) AS receipts,MAX(generation) AS generation
                 FROM viewer_live_receipts WHERE start_ns=?''',(FAILED_START_NS,))
        result['failed_window']=dict(start_utc='2026-10-27T05:20:00Z',
            checkpoint_still_at_failed_window=expected,windows=published['windows'],
            receipts=receipts['receipts'],observed_published=bool(published['windows'] and receipts['receipts']),
            no_partial_publication_in_headers=not bool(published['windows'] != receipts['receipts']))
        # Exact paths only, never print free-text operator notes.
        paths=sorted(p for p in OWNER_CONFIRMED if p.startswith('Public.v1/'))
        rows={r['service_path']:r for r in db.all('''SELECT service_path,role,initiation,source,reviewed
              FROM viewer_service_roles WHERE service_path IN ('''+','.join('?' for _ in paths)+')',paths)}
        result['confirmed_paths']=[dict(path=p,expected_role=OWNER_CONFIRMED[p][0],
            expected_initiation=OWNER_CONFIRMED[p][1],observed_role=rows[p]['role'] if p in rows else None,
            observed_initiation=rows[p]['initiation'] if p in rows else None,
            reviewed=bool(rows[p]['reviewed']) if p in rows else None,
            aligned=(rows[p]['role'],rows[p]['initiation'])==OWNER_CONFIRMED[p] if p in rows else False)
            for p in paths]
        result['catalog_state']=db.one('''SELECT fingerprint,changed_paths,changed_requests,semantic_changes
                                              FROM viewer_service_catalog_state WHERE id=1''')
        result['postgres_settings']={r['name']:r['setting']+' '+r['unit'] if r['unit'] else r['setting']
            for r in db.all('''SELECT name,setting,unit FROM pg_settings
                            WHERE name IN ('work_mem','shared_buffers','effective_cache_size',
                                           'max_parallel_workers_per_gather','random_page_cost')''')}
        result['relations']=db.all('''SELECT c.relname AS name, c.reltuples::bigint AS estimated_rows,
            pg_total_relation_size(c.oid) AS total_bytes,
            coalesce(s.seq_scan,0) AS historical_seq_scans,
            coalesce(s.idx_scan,0) AS historical_index_scans,
            s.last_analyze::text AS last_analyze,s.last_autoanalyze::text AS last_autoanalyze
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            LEFT JOIN pg_stat_all_tables s ON s.relid=c.oid
            WHERE n.nspname=current_schema() AND c.relkind='r'
               AND c.relname IN ('viewer_events','viewer_links','viewer_requests','viewer_actions',
                                  'viewer_raw_events','viewer_event_captures')
            ORDER BY c.relname''')
        result['event_indexes']=db.all('''SELECT i.relname AS index_name,
                        pg_get_indexdef(i.oid) AS definition
            FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid
            JOIN pg_class t ON t.oid=x.indrelid
            JOIN pg_namespace n ON n.oid=t.relnamespace
            WHERE n.nspname=current_schema() AND t.relname='viewer_events'
            ORDER BY i.relname''')
        # Roll back the strictly read-only transaction, to avoid reliance on
        # the context manager closing out a cursor after timeout.
        db.conn.rollback()
        return result

def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config',type=Path,required=True)
    ap.add_argument('--out',type=Path,default=Path('validation/d0_d1_readonly.json'))
    args=ap.parse_args(argv)
    try:
        result=diagnose(args.config.resolve());status=0
    except Exception as e:
        # No server error strings: they can contain identifiers or SQL text.
        result=dict(status='D0_FAILED',error_type=type(e).__name__,
                    error_code=str(e) if isinstance(e,ValueError) and str(e) in (
                        'D0_REQUIRES_EXACT_p24_design_viewer','LIVE_STATE_MISSING') else 'see_local_console',
                    no_ingest_or_checkpoint_change=True)
        status=2
    atomic_json(args.out,result)
    print(json.dumps(dict(status=result['status'],output=str(args.out)),ensure_ascii=False))
    return status

if __name__=='__main__':raise SystemExit(main())
