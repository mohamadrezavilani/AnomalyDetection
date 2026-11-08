"""Bounded first assessment, strict page fences and updating shared references."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import json

from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window,read_window,read_fresh_burst,owned_context
from anomaly_detection.product_engine import evaluate_job
from anomaly_detection.product_diagnostics import read_queue
from anomaly_detection.product_dependencies import context_changed
from anomaly_detection.service_reference import model,import_roots
from anomaly_detection.snapshot import canonical,digest

ROOT=Path(__file__).resolve().parents[2]
TARGET=1_800_000_000_000_000_000//FIVE_NS*FIVE_NS
SESSION='a'*64
SERVICES=('Public.v1/ExchangeCurrency','Public.v1/ExchangeGold','Services.v1/WaterBills','Services.v1/ElectricBills')


def metadata(at=TARGET):
    return {'namespace':'viewer:fixture','stream_key':'fixture','keys_fingerprint':'fixture',
        'generation':100,'semantic_generation':100,'captured_at_ns':at+FIVE_NS,'next_ns':at+FIVE_NS,
        'retention_cutoff_ns':0,'catalog_fingerprint':'fixture'}


def packet(at,counts,session=SESSION,offset=100000):
    rows=[]
    for service,n in counts.items():
        for _ in range(n):
            i=offset+len(rows)
            rows.append({'request_key':f'{i:064x}','anchor_key':'ba1:'+f'{i+1000000:064x}',
                'session_key':session,'request_session_key':session,'anchor_ns':at+len(rows)+1,
                'kind':'service_execution','state':'active','revision':1,'root_call':service,
                'root_code':'G00000','identity_state':'assigned','conflicted':False})
    return {'target_ns':at,'source':metadata(at),'stamp':str(at),'available':True,
        'rows':rows,'has_more':False,'after':None}


def main():
    engine=Engine();checks={}
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection')
        store=ProductStore(raw);store.initialize()
        # Reproduce interrupted enumeration while unrelated publications move
        # the global generation; no partial population is ever admitted.
        rows=packet(TARGET-10*FIVE_NS,{SERVICES[0]:9},offset=1)['rows']
        class Source:
            page_size=3
            generation=2
            @contextmanager
            def snapshot(self):yield self.query
            def metadata(self,q):return dict(metadata(TARGET-10*FIVE_NS),generation=self.generation,semantic_generation=self.generation)
            def query(self,sql,args=(),**kwargs):
                if 'viewer_live_windows' in sql:
                    return [{'start_ns':TARGET-10*FIVE_NS,'end_ns':TARGET-9*FIVE_NS,'generation':1,'last_publish_ns':1}]
                after=args[2] if len(args)>3 else -1
                return [r for r in rows if r['anchor_ns']>after][:self.page_size+1]
        source=Source()
        for _ in range(8):
            result=apply_window(store,read_window(source,store.state('fresh_cursor')))
            source.generation+=1
        assert result['status']=='RESTART_SNAPSHOT'
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_source_windows WHERE complete=TRUE').fetchone()['n']==0
        checks['sparse_page_scheduling_under_global_generation_changes_can_restart_forever']='REPRODUCED'
        burst=read_fresh_burst(source,store,clock=SimpleNamespace(monotonic=lambda:0))
        assert burst[-1]['status']=='COMPLETE' and len(burst)==3
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_facts').fetchone()['n']==9
        checks['bounded_consecutive_reads_finish_without_weakening_any_generation_fence']='PASS'
        # Four different services learn from qualified, past-only canonical
        # points; no service-specific seed or count threshold is installed.
        values=[]
        for service in SERVICES:
            for i in range(120):
                values.append((service,'service_execution',f'{i+1000:064x}',TARGET-(i+1)*3*FIVE_NS,1+i%3,True))
        with raw.cursor() as cursor:
            cursor.executemany('INSERT INTO anomaly_detection.adp_service_reference_points VALUES(%s,%s,%s,%s,%s,%s)',values)
        for i,service in enumerate(SERVICES):
            at=TARGET+i*FIVE_NS
            apply_window(store,packet(at,{service:40},offset=200000+i*1000))
            for f in raw.execute('SELECT request_key,body FROM anomaly_detection.adp_facts WHERE session_key=%s AND at_ns>=%s AND at_ns<%s',
                (SESSION,at,at+FIVE_NS)).fetchall():
                e=json.loads(f['body']);fact={'source_present':True,'semantic':e,'quality':{'evidence_available':True},
                    'transport':{'root_call':service},'observations':[],'identifiers':[],'relations':[],
                    'evidence':[{'origin_key':digest(['origin',f['request_key']]),'version_key':digest(['version',f['request_key']]),
                        'callpath':service,'at_ns':e['anchor_ns'],'qualified':True,'raw_available':True}]}
                raw.execute('UPDATE anomaly_detection.adp_facts SET details=%s,details_digest=%s WHERE request_key=%s',
                    (canonical(fact),digest(fact),f['request_key']))
            j=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION,at)).fetchone())
            c=store.save_context(j,owned_context(store,j));j['version']=c['job_version']
            result=evaluate_job(store,j,c,TARGET+20*FIVE_NS)
            decision=next(d for d in result['decisions'] if d['family']=='peer_service_rate_5m')
            assert decision['status']=='CANDIDATE' and decision['observed']==40
            assert decision['baseline_unit']=='canonical_service_executions'
            case=raw.execute('SELECT state FROM anomaly_detection.adp_incidents WHERE session_key=%s AND target_ns=%s',(SESSION,at)).fetchone()
            assert case['state']=='NEEDS_REVIEW'
        checks['currency_gold_water_and_electricity_use_one_general_reference_method']='PASS_SYNTHETIC_QUALIFIED_CANONICAL_INPUTS'
        # A very old unfinished job and a frozen fairness pass cannot consume
        # the live lane. A future/incomplete source window is not eligible.
        old=TARGET-100*FIVE_NS
        raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns) VALUES(%s,%s)',('b'*64,old))
        current=TARGET+4*FIVE_NS
        combined=packet(current,{SERVICES[2]:60,SERVICES[3]:60},offset=400000)
        combined['rows']+=packet(current,{SERVICES[0]:4},session='c'*64,offset=500000)['rows']
        apply_window(store,combined)
        future=packet(current+FIVE_NS,{SERVICES[0]:200},session='d'*64,offset=600000)
        store.apply_rows(future['rows'],future['source'])
        store.ready_pass={'begin':old,'end':TARGET,'after':None,'first_visit':True}
        selected=store.next_live_job(TARGET+30*FIVE_NS)
        assert selected['session_key']==SESSION and selected['target_ns']==current and selected['observed_count']==120
        assert store.next_job(TARGET+30*FIVE_NS,recent=False)['target_ns']==old
        assert store.next_backlog_job(TARGET+30*FIVE_NS)['session_key']==SESSION
        checks['live_first_assessment_prioritizes_busy_ready_scope_without_dropping_old_history']='PASS'
        checks['unpublished_future_population_cannot_enter_live_ready_lane']='PASS'
        raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=TRUE,version=version+1,due_ns=0 WHERE session_key=%s AND target_ns=%s',
            (SESSION,TARGET))
        reassess=store.next_candidate_job(TARGET+30*FIVE_NS)
        assert reassess and reassess['last_evaluated_ns'] is not None
        assert reassess['processed_version']!=reassess['version']
        checks['changed_candidate_evidence_has_reserved_reassessment_after_initial_evaluation']='PASS'
        # Once the newest published edge moves ahead, an older busy first
        # assessment still has a reserved path outside the ten-minute band.
        edge=current+20*FIVE_NS
        raw.execute('INSERT INTO anomaly_detection.adp_source_windows VALUES(%s,%s,%s,TRUE)',(edge,str(edge),canonical(metadata(edge))))
        assert store.next_live_job(TARGET+50*FIVE_NS) is None
        assert store.next_backlog_job(TARGET+50*FIVE_NS)['target_ns']==current
        checks['older_busy_first_assessment_keeps_a_path_after_exiting_live_band']='PASS'
        # Upgrade fills priority metadata in bounded batches and never alters
        # dirty/version/CAS state or any target counts.
        raw.execute('UPDATE anomaly_detection.adp_jobs SET observed_count=NULL WHERE target_ns=%s',(current,))
        before=raw.execute('SELECT version,dirty FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION,current)).fetchone()
        store.warm_live_priorities(limit=1)
        after=raw.execute('SELECT version,dirty,observed_count FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION,current)).fetchone()
        assert before['version']==after['version'] and before['dirty']==after['dirty'] and after['observed_count']==120
        checks['bounded_priority_upgrade_is_not_model_input_or_job_version_mutation']='PASS'
        # Existing HTTP bootstrap is a fallback, not a seven-day freeze over a
        # now qualified canonical baseline.
        service=SERVICES[1]
        seed={'dataset_id':'hr1:seed','service_path':service,'begin_ns':TARGET-400*FIVE_NS,'cutoff_ns':TARGET,
            'calls':[],'cases':[],'qualification':{'unit':'observed_direct_client_request_roots'}}
        for i in range(120):seed['calls'].append({'request_key':f'{800000+i:064x}','session_key':f'{9000+i:064x}',
            'at_ns':TARGET-(i+1)*3*FIVE_NS,'origin':'synthetic'})
        import_roots(store,seed,TARGET+FIVE_NS)
        ref,_=model(store,service,'e'*64,TARGET+4*FIVE_NS,'service_execution')
        assert ref['unit']=='canonical_service_executions' and ref['upper']>=3
        checks['qualified_ongoing_canonical_history_supersedes_finite_http_seed']='PASS'
        store.model_cache.clear();store.reference_inputs_cache.clear()
        original=engine.query;reads=[]
        def counted(role,sql,params):
            if isinstance(sql,str) and 'FROM anomaly_detection.adp_service_reference_points' in sql and 'GROUP BY session_key' in sql:
                reads.append(sql)
            return original(role,sql,params)
        engine.query=counted
        first,epochs=model(store,service,'e'*64,TARGET,'service_execution')
        second,_=model(store,service,'f'*64,TARGET,'service_execution')
        assert len(reads)==1 and first['reference_values']==second['reference_values']
        checks['different_sessions_share_one_versioned_reference_input_query']='PASS'
        with store.transaction():
            raw.execute('UPDATE anomaly_detection.adp_service_reference_points SET value=35 WHERE service_path=%s AND session_key=%s',
                        (service,f'{1000:064x}'))
            from anomaly_detection.model_queue import reference_changed
            reference_changed(store,[(service,TARGET-3*FIVE_NS)])
        changed,new_epochs=model(store,service,'e'*64,TARGET,'service_execution')
        assert changed['upper']==35 and new_epochs!=epochs and len(reads)==2
        checks['late_reference_correction_invalidates_shared_cache_by_epoch']='PASS'
        diagnostic=read_queue(raw,TARGET+30*FIVE_NS)
        queued=next(r for r in diagnostic['pending_recent_sample'] if r['session_key']==SESSION and r['target_ns']==current)
        assert queued['total_observed_executions']==120 and sorted(queued['counts_by_service'].values())==[60,60]
        assert queued['queue_state']=='PENDING_FIRST_EVALUATION' and not diagnostic['models_executed']
        incomplete=next(r for r in diagnostic['pending_recent_sample'] if r['session_key']=='d'*64)
        assert incomplete['queue_state']=='WAITING_FOR_COMPLETE_WINDOW'
        checks['persisted_diagnostic_distinguishes_missing_window_proof_from_evaluation_queue']='PASS'
        # Reinitialization is idempotent after metadata upgrade.
        store.initialize()
        assert raw.execute('SELECT observed_count FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',
            (SESSION,current)).fetchone()['observed_count']==120
        checks['metadata_migration_is_idempotent_and_preserves_existing_jobs']='PASS'
        report={'build_id':BUILD_ID,'status':'PASS_REVISION10_OFFLINE','checks':checks,
            'environment':'ISOLATED_POSTGRESQL_WASM','owner_connections':0,
            'native_windows_postgresql':'NOT_RUN','native_new_test_results':'NOT_RUN',
            'native_latency':'NOT_MEASURED','precision_recall':'NOT_EVALUATED'}
        (ROOT/'validation/PRODUCT_revision10.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report))
    finally:engine.close()


if __name__=='__main__':main()
