"""Finite SQL/transaction qualification in an EMPTY disposable Viewer DB.

No database/table reset or deletion of pre-existing data. Supply a separate
p24_design_*_qualification database, never the populated Viewer database.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_online import (initialize_live,bind_stream,publish_capture,FIVE_NS,single_worker)
from tools.qualify_viewer_online import projection_digest
from tests.test_viewer_online import verified_file,START
from tests.test_viewer_r6_service_journey import log,sql


def qualify(config,out):
    name=str(config.get('dbname',''))
    if not name.startswith('p24_design_') or not name.endswith('_qualification'):
        raise ValueError('requires_empty_p24_design_qualification_database')
    checks={}
    with tempfile.TemporaryDirectory() as t:
        p=Path(t);keys=p/'keys.json';generate_keys(keys)
        with ViewerDB(config=config,keys_path=keys) as db:
            db.init();initialize_live(db)
            if db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'] or db.one('SELECT COUNT(*) AS n FROM viewer_live_state')['n']:
                raise ValueError('qualification_database_not_empty')
            engine=db.one('SELECT version() AS v')['v']
            copy_transport='native_psycopg_copy'
            if 'PGlite' in engine:
                # PGlite's socket shim doesn't implement COPY FROM STDIN.
                # Qualify the same staging/merge SQL with bound rows; record
                # this explicitly rather than claiming native COPY coverage.
                def stage_rows(stage,columns,values):
                    db.many('INSERT INTO '+stage+' ('+columns+') VALUES ('+
                            ','.join('?' for _ in values[0])+')',values)
                db._copy_ingest_stage=stage_rows
                def final_rows(stage,table,columns,order):
                    db.sql('INSERT INTO '+table+' ('+columns+') SELECT '+columns+' FROM '+stage+' ORDER BY '+order)
                db._copy_ingest_stage_into_table=final_rows
                copy_transport='bound_row_adapter_NATIVE_COPY_NOT_RUN'
            bind_stream(db,start_ns=START,stream_key='finite_sql_qualification')
            rows=[log(1,'pay','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K')),
                  log(2,'pay','Core.v1/WalletPayment Line:1','POST (G00000 | successful)'),
                  log(3,'ask','Services.v1/WaterBills Line:3','POST (G00000 | successful)')]
            # Cross ingestion and named-contract-cursor batch boundaries on the
            # actual PostgreSQL protocol, including pipeline synchronization.
            for i in range(600):
                rows.extend([log(1000+2*i,'bulk_'+str(i),'Services.v1/WaterBills Line:3','POST (G00000 | successful)'),
                    log(1001+2*i,'bulk_'+str(i),'DBPath.x.ud_prc_invoiceRegister',
                        sql('ud_prc_invoiceRegister',invoiceUniqueID='bulk_invoice_'+str(i)))])
            a=verified_file(p/'a.gz',rows)
            with single_worker(db,p/'unused_pg.lock'):
                history_oid=db.one("SELECT 'viewer_action_history'::regclass::oid AS n")['n']
                ingest_statements=[];copy_sizes=[];final_transports=[];merge_events=[]
                db.progress_callback=lambda event:merge_events.append(event) if event['stage']=='ingest_merge_complete' else None
                original_sql=db.sql;original_copy=db._copy_ingest_stage
                original_final_copy=db._copy_ingest_stage_into_table
                def trace_ingest(statement,params=()):
                    if 'viewer_stage_' in statement:ingest_statements.append(statement)
                    return original_sql(statement,params)
                def bounded_copy(stage,columns,values):
                    copy_sizes.append(len(values));return original_copy(stage,columns,values)
                def trace_final_copy(stage,table,columns,order):
                    final_transports.append(table)
                    return original_final_copy(stage,table,columns,order)
                db.sql=trace_ingest;db._copy_ingest_stage=bounded_copy
                db._copy_ingest_stage_into_table=trace_final_copy
                try:first=publish_capture(db,a,START,START+FIVE_NS)
                finally:
                    db.sql=original_sql;db._copy_ingest_stage=original_copy
                    db._copy_ingest_stage_into_table=original_final_copy
                    db.progress_callback=None
                checks['bootstrap_published']=first['bootstrap']
                checks['postgres_staging_merge_crossed_500_event_batches']=db.one('SELECT COUNT(*) AS n FROM viewer_events')['n']==1203
                merges=[q for q in ingest_statements if q.startswith('INSERT INTO ') and ' FROM viewer_stage_' in q]
                # Count real table merges, not adapter implementation details:
                # the WASM COPY substitute itself emits INSERT SELECT too.
                merged_tables=[event['table'] for event in merge_events]
                truncations=[q for q in ingest_statements if q.startswith('TRUNCATE TABLE viewer_stage_')]
                checks['one_final_merge_and_stage_reset_per_table_per_capture']=(
                    len(merged_tables)==len(set(merged_tables))==4 and len(truncations)==4)
                checks['copy_buffers_remain_bounded_at_500_source_events']=max(copy_sizes)<=500 and len(copy_sizes)>4
                checks['contract_server_cursor_crossed_400_events']=db.one('SELECT COUNT(*) AS n FROM viewer_contract_identifiers')['n']>=600
                checks['history_relation_preserved_for_snapshot_readers']=history_oid==db.one("SELECT 'viewer_action_history'::regclass::oid AS n")['n']
                previous=projection_digest(db)
                second=[log(4,'cb','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K')),
                        log(5,'cb','PaymentCallback.PaymentCallback Line:1','POST (G00000 | successful)')]
                for row in second:row['@timestamp']='2026-10-24T04:20:01Z'
                b=verified_file(p/'b.gz',second,START+FIVE_NS)
                def crash(stage):
                    if stage=='after_relations':raise RuntimeError('controlled_rollback')
                try:publish_capture(db,b,START+FIVE_NS,START+2*FIVE_NS,fault=crash)
                except RuntimeError:pass
                checks['rollback_preserved_all_projections']=previous==projection_digest(db)
                info=publish_capture(db,b,START+FIVE_NS,START+2*FIVE_NS)
                checks['incremental_dependency_scope']=info['impacted_requests']==2 and not info['bootstrap']
                scoped_keys=[row['request_key'] for row in db.all('SELECT request_key FROM viewer_projection_scope')]
                physical_before=db.all('SELECT request_key,ctid::text AS tid FROM viewer_requests ORDER BY request_key')
                db.rebuild(request_keys=scoped_keys,commit=False)
                db.rebuild_payment_contract(request_keys=scoped_keys,commit=False)
                checks['unchanged_scoped_rebuild_preserves_permanent_row_versions']=(
                    physical_before==db.all('SELECT request_key,ctid::text AS tid FROM viewer_requests ORDER BY request_key'))
                checks['no_permanent_work_relations']=db.one("""SELECT COUNT(*) AS n FROM pg_class c
                    JOIN pg_namespace n ON n.oid=c.relnamespace
                    WHERE n.nspname=current_schema() AND c.relname LIKE ?""",('viewer_build_%',))['n']==0
                db.conn.commit()
                checks['checkpoint_advanced_once']=db.one('SELECT COUNT(*) AS n FROM viewer_live_receipts')['n']==2
                # Exercise the same scoped cache used by the native publisher,
                # with unrelated retained requests present in the database.
                ask=db.lookup_request('ask')['request_key']
                db.rebuild(request_keys=[ask],commit=False)
                checks['scoped_event_cache_excludes_unrelated_history']=(
                    db.one('SELECT COUNT(*) AS n FROM viewer_projection_events')['n']==1)
                plan=db.one('''EXPLAIN (FORMAT JSON) SELECT e.* FROM viewer_projection_scope s
                    CROSS JOIN LATERAL (SELECT source.* FROM viewer_events source
                        WHERE source.request_key=s.request_key OFFSET 0) e''')['QUERY PLAN']
                def nodes(value):
                    if isinstance(value,dict):
                        yield value
                        for child in value.values():yield from nodes(child)
                    elif isinstance(value,list):
                        for child in value:yield from nodes(child)
                checks['scoped_fetch_plan_uses_request_key_index']=any(
                    'request_key' in str(node.get('Index Cond','')) for node in nodes(plan))
                db.conn.rollback()
                original=projection_digest(db)
                publish_capture(db,a,START,START+FIVE_NS,mode='recheck')
                checks['duplicate_recheck_idempotent']=original==projection_digest(db)
                db.update_service_role('Services.v1/WaterBills','support','unknown','qualification only')
                checks['role_and_summary_atomic']=db.semantic_sessions()['total']==0
                original=projection_digest(db)
                db.rebuild();db.rebuild_payment_contract();db.build_semantic_index()
                checks['incremental_equals_full_batch']=original==projection_digest(db)
                db.init_contract_candidate_scope();db.conn.commit()
                db.sql('SET TRANSACTION READ ONLY')
                db.sql('DELETE FROM viewer_projection_scope')
                scope=[(row['request_key'],) for row in db.all('SELECT request_key FROM viewer_requests WHERE root_call=?',('Services.v1/WaterBills Line:3',))]
                db.many('INSERT INTO viewer_projection_scope VALUES (?)',scope)
                timings={}
                original_sql=db.sql;payload_query=[]
                def trace_payload(statement,params=()):
                    if statement.startswith('SELECT k.origin_key,k.version_key,body.payload') and not payload_query:
                        payload_query.append((statement,params))
                    return original_sql(statement,params)
                db.sql=trace_payload
                try:
                    with db.contract_event_batches(scoped=True,timings=timings,prepared_scope=True) as batches:
                        selected=[row for batch in batches for row in batch]
                finally:db.sql=original_sql
                checks['scoped_fetch_crosses_400_bodies_in_read_only_transaction']=len(selected)==600 and timings['candidate_events']==600
                db.conn.rollback()
                checks['scoped_reader_preserves_all_projections']=original==projection_digest(db)
                query,params=payload_query[0]
                plan=next(iter(db.one('EXPLAIN (FORMAT JSON) '+query,params).values()))[0]['Plan']
                def indexes(node):
                    result=[node.get('Index Name')] if node.get('Relation Name')=='viewer_raw_events' else []
                    for child in node.get('Plans',[]):result.extend(indexes(child))
                    return result
                checks['scoped_payload_plan_uses_raw_primary_key']=('viewer_raw_events_pkey' in indexes(plan))
                identity_queries=[];original_sql=db.sql
                def trace_identity(statement,params=()):
                    if statement.startswith('SELECT body.value FROM viewer_events e CROSS JOIN LATERAL'):
                        identity_queries.append((statement,params))
                    return original_sql(statement,params)
                sample=db.one('SELECT request_key,session_key FROM viewer_requests WHERE session_key IS NOT NULL LIMIT 1')
                expected_session=db.one('''SELECT b.raw_session_id AS value FROM viewer_events e
                    JOIN viewer_raw_events b ON b.origin_key=e.origin_key AND b.version_key=e.version_key
                    WHERE e.session_key=? AND b.raw_session_id IS NOT NULL LIMIT 1''',(sample['session_key'],))['value']
                expected_request=db.one('''SELECT b.raw_request_id AS value FROM viewer_events e
                    JOIN viewer_raw_events b ON b.origin_key=e.origin_key AND b.version_key=e.version_key
                    WHERE e.request_key=? AND b.raw_request_id IS NOT NULL LIMIT 1''',(sample['request_key'],))['value']
                db.sql=trace_identity
                try:
                    checks['home_raw_session_and_request_aliases_preserved']=(
                        db.raw_session_id(sample['session_key'])==expected_session and
                        db.raw_request_id(sample['request_key'])==expected_request and
                        db.raw_session_id('f'*64) is None)
                finally:db.sql=original_sql
                identity_plans=[]
                for query,params in identity_queries:
                    identity_plans.append(next(iter(db.one('EXPLAIN (FORMAT JSON) '+query,params).values()))[0]['Plan'])
                checks['home_raw_aliases_use_primary_key_lookups_without_global_raw_scan']=all(
                    indexes(plan) and all(name=='viewer_raw_events_pkey' for name in indexes(plan)) for plan in identity_plans)
                from tools.diagnose_viewer_fetch import probe_readers
                db.sql('DELETE FROM viewer_projection_scope')
                db.many('INSERT INTO viewer_projection_scope VALUES (?)',scope)
                db.conn.commit()
                comparison=probe_readers(db,events=400)
                checks['bounded_read_only_probe_matches_original_first_400_events']=comparison['status']=='READERS_MATCH' and comparison['first_batch_equal']
                # Metadata-only capture and a true revision of an existing
                # origin must keep their distinct semantics across batches.
                import copy
                old=rows[2]
                extra=[log(20000+i,'revision_'+str(i),'Services.v1/WaterBills Line:1','POST (G00000 | successful)') for i in range(501)]
                projected=dict(old,_score=1)
                revised=dict(old,RequestID='reassigned',message='POST (GD2016 | failed)')
                db.sql('SAVEPOINT qualification_revisions')
                new_projection=dict(extra[0],_score=1)
                new_revision=dict(extra[0],RequestID='reassigned_new',message='POST (GD2016 | failed)')
                result=db.ingest([verified_file(p/'revisions.gz',extra+[
                    copy.deepcopy(extra[0]),new_projection,new_revision,
                    copy.deepcopy(old),projected,revised])],commit=False)[0]
                checks['staging_preserves_duplicates_projection_and_revision']=(result['new_events'],result['duplicates'],result['conflicts'])==(503,4,2)
                db.sql('ROLLBACK TO SAVEPOINT qualification_revisions');db.sql('RELEASE SAVEPOINT qualification_revisions')
                db.sql('SAVEPOINT qualification_multiple_files')
                files=[verified_file(p/'multi_a.gz',extra[:501]),
                       verified_file(p/'multi_b.gz',[copy.deepcopy(extra[0]),extra[-1],
                           log(99999,'next_file','Services.v1/WaterBills Line:1','POST (G00000 | successful)')])]
                imported=db.ingest(files,commit=False)
                checks['multiple_files_in_one_transaction_reuse_stages_without_remerging_old_rows']=(
                    [r['new_events'] for r in imported]==[501,1] and imported[1]['duplicates']==2)
                db.sql('ROLLBACK TO SAVEPOINT qualification_multiple_files');db.sql('RELEASE SAVEPOINT qualification_multiple_files')
                before=db.one('SELECT COUNT(*) AS n FROM viewer_events')['n']
                original_sql=db.sql
                def fail_merge(statement,params=()):
                    if statement.startswith('INSERT INTO viewer_raw_events (') and ' FROM viewer_stage_raw_events' in statement:
                        raise RuntimeError('controlled_merge_failure')
                    return original_sql(statement,params)
                db.sql=fail_merge
                try:
                    try:db.ingest([verified_file(p/'merge_failure.gz',extra)],commit=False)
                    except RuntimeError:pass
                finally:db.sql=original_sql
                checks['failure_between_table_merges_rolls_back_already_merged_events']=(
                    db.one('SELECT COUNT(*) AS n FROM viewer_events')['n']==before and projection_digest(db)==original)
                before=db.one('SELECT COUNT(*) AS n FROM viewer_events')['n']
                bad=extra[:];bad[-1]=dict(bad[-1],message=None)
                failed=False
                try:db.ingest([verified_file(p/'invalid.gz',bad)],commit=False)
                except ValueError:failed=True
                checks['staging_error_after_first_batch_rolls_back']=failed and db.one('SELECT COUNT(*) AS n FROM viewer_events')['n']==before
                # A retained source catalogue upgrade must update historical
                # actions/anchors, not only the next ingested window.
                from p24_foundation.viewer_data import token
                migration_rows=[log(50000+i,'catalog_'+str(i),'Services.v1/PostTrackingExtended Line:7','POST (G00000 | successful)') for i in range(601)]
                db.ingest([verified_file(p/'catalog_history.gz',migration_rows)])
                migration_keys=[token(db.keys,'request','catalog_'+str(i)) for i in range(601)]
                db.rebuild(request_keys=migration_keys);db.reconcile_semantic_requests(migration_keys)
                db.sql("UPDATE viewer_service_roles SET role='unknown',source='unclassified',reviewed=0 WHERE service_path=?",('Services.v1/PostTrackingExtended',))
                db.sql("UPDATE viewer_actions SET category='unknown' WHERE name='PostTrackingExtended'")
                db.sql("UPDATE viewer_semantic_occurrences SET category='unknown' WHERE root_call=?",('Services.v1/PostTrackingExtended Line:7',))
                db.sql("UPDATE viewer_service_catalog_state SET fingerprint='previous_catalog'");db.conn.commit()
                before_migration=projection_digest(db);raw_count=db.one('SELECT COUNT(*) AS n FROM viewer_events')['n']
                old_cursor=db.one('SELECT next_ns FROM viewer_live_state')['next_ns'];db.conn.commit()
                def fail_catalog(stage):
                    if stage=='catalog_sync_after_actions':raise RuntimeError('controlled_catalog_rollback')
                try:db.sync_service_catalog(fault=fail_catalog)
                except RuntimeError:pass
                checks['source_catalog_upgrade_failure_rolls_back_all_projections']=before_migration==projection_digest(db)
                info=db.sync_service_catalog()
                checks['source_catalog_updates_retained_actions_across_500_request_batches']=(
                    info['changed_requests']>=601 and db.one("SELECT COUNT(*) AS n FROM viewer_actions WHERE name='PostTrackingExtended' AND category='business'")['n']==601)
                operator=db.one('SELECT role,source,reviewed FROM viewer_service_roles WHERE service_path=?',('Services.v1/WaterBills',))
                checks['source_catalog_preserves_operator_role_raw_events_and_live_cursor']=(
                    operator==dict(role='support',source='operator',reviewed=1) and
                    db.one('SELECT COUNT(*) AS n FROM viewer_events')['n']==raw_count and
                    db.one('SELECT next_ns FROM viewer_live_state')['next_ns']==old_cursor)
                stable=projection_digest(db)
                checks['source_catalog_repeat_is_idempotent']=db.sync_service_catalog()['status']=='CURRENT' and stable==projection_digest(db)
                db.conn.rollback();db.sql('SET TRANSACTION READ ONLY')
                checks['source_catalog_status_reads_inside_read_only_transaction']=db.service_catalog_status()['status']=='CURRENT'
                db.conn.rollback()
            # This is sequential protocol qualification. Native PG multi-client
            # snapshot/reconnect/kill tests and owner pilot are separate gates.
            report=dict(status='PASS' if all(checks.values()) else 'FAIL',
                mode='postgresql_dialect_wasm' if 'PGlite' in engine else 'native_postgresql_finite_sql',
                engine=engine,checks=checks,live_elasticsearch='NOT_RUN',
                copy_transport=copy_transport,
                multi_client_native_concurrency='NOT_RUN',owner_windows='NOT_RUN',production_modified=False)
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return report


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config',type=Path,required=True);ap.add_argument('--out',type=Path,required=True)
    args=ap.parse_args(argv)
    spec=importlib.util.spec_from_file_location('postgres_qualification_config',args.config.resolve())
    cfg=importlib.util.module_from_spec(spec);spec.loader.exec_module(cfg)
    try:report=qualify(cfg.DATABASE,args.out)
    except Exception as exc:
        print(json.dumps(dict(status='FAILED',error=type(exc).__name__)));return 2
    print(json.dumps(dict(status=report['status'],mode=report['mode'],checks=report['checks'])))
    return 0 if report['status']=='PASS' else 2

if __name__=='__main__':raise SystemExit(main())
