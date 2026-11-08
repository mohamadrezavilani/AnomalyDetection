"""Regression for the four review defects, full-window reuse and pinned bridge.

Run with PYTHONPATH=<AnomalyDetection root>, the existing psycopg test dependency,
and test-only PGlite installed beside this file. Never connects to owner's PG.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
from transport import Engine
from anomaly_detection import FIVE_NS,SOURCE_SHA,CATALOG_SHA,BUILD_ID
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_source import ProductSource
from anomaly_detection.product_engine import evaluate_job
from anomaly_detection.product_dependencies import peer_model,context_changed
from anomaly_detection.product_pipeline import read_window,apply_window,owned_context
from anomaly_detection.snapshot import canonical,digest,ContractError
from tests.fixture_factory import initial,START,SESSION_A,key

ROOT=Path(__file__).resolve().parents[2]

def main():
    engine=Engine();checks={};source={'namespace':'viewer:review','stream_key':'review','keys_fingerprint':'review',
        'generation':11,'semantic_generation':11,'captured_at_ns':START+1000*FIVE_NS}
    try:
        schema=json.loads((ROOT/'reference/handoff_20261031/reference/viewer_schema_reference.json').read_text())['tables']
        for name,spec in schema.items():
            columns=[f'"{c["name"]}" '+{'INTEGER':'BIGINT','BLOB':'BYTEA','REAL':'DOUBLE PRECISION'}.get(c['declared_type'],c['declared_type']) for c in spec['columns']]
            engine.query('postgres','CREATE TABLE public."'+name+'"('+','.join(columns)+')',())
        def insert(table,row):
            allowed={c['name'] for c in schema[table]['columns']};row={k:v for k,v in row.items() if k in allowed};cols=list(row)
            engine.query('postgres','INSERT INTO public."'+table+'"('+','.join('"'+c+'"' for c in cols)+') VALUES ('+
                ','.join('$'+str(i+1) for i in range(len(cols)))+')',[row[c] for c in cols])
        fixture=initial()
        for table,rows in fixture['tables'].items():
            for row in rows:insert(table,row)
        for r in fixture['tables']['viewer_events']:insert('viewer_raw_events',{'origin_key':r['origin_key'],'version_key':r['version_key']})
        for r in fixture['tables']['viewer_semantic_occurrences']:
            insert('viewer_actions',{'action_key':r['request_key'],'root_request_key':r['request_key'],'category':r['category'],'initiation':'unknown'})
        insert('viewer_live_state',{'id':1,'stream_key':'review','keys_fingerprint':'review','generation':11,'next_ns':START+2*FIVE_NS,'lag_seconds':60,'last_error':None})
        insert('viewer_semantic_checkpoint',{'id':1,'generation':11,'state':'ready'})
        insert('viewer_service_catalog_state',{'id':1,'fingerprint':CATALOG_SHA})
        for start,end in fixture['scope']['complete_intervals_ns']:insert('viewer_live_windows',{'start_ns':start,'end_ns':end,'generation':11,'last_publish_ns':START+3*FIVE_NS})
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize();store.bind(source)
        session='c'*64;target=START+121*FIVE_NS;service='Services.v1/PostPackagesStatus'
        raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,version) VALUES(%s,%s,7)',(session,target))
        job=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(session,target)).fetchone())
        context={'session_key':session,'target_ns':target,'source':source,'windows':[{'start_ns':target,'coverage_complete':True,'population_complete':True,
            'counts':{service:100},'witnesses':{},'first_observed_ns':None}], 'events':[],'target_complete':True,'target_events_complete':True,'job_version':7}
        raw.execute('INSERT INTO anomaly_detection.adp_contexts VALUES(%s,%s,%s,%s,%s,%s)',(session,target,canonical(context),digest(context),source['captured_at_ns'],7))
        store.invalidate(session,START)
        changed=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(session,target)).fetchone())
        assert changed['version']>7 and store.context(changed) is None
        checks['F03_dirty_cached_context_invalidated']='PASS'
        try:store.save_context(job,context)
        except ContractError as exc:assert str(exc)=='PRODUCT_CONTEXT_INPUT_CHANGED_RETRY'
        else:raise AssertionError('stale source fetch adopted newer job version')
        checks['stale_fetch_cannot_adopt_new_version']='PASS'
        packet={'source':source,'target_ns':START,'available':True,'rows':[{'service_path':service,'value':5.,'sessions':30,'population_valid':1}]}
        for n in range(120):store.apply_cohort(dict(packet,target_ns=target-(n+1)*FIVE_NS),advance=False)
        context=store.save_context(changed,context);changed=dict(changed,version=context['job_version'])
        result=evaluate_job(store,changed,context,source['captured_at_ns'])
        assert any(d['family']=='rate_5m' and d['status']=='CANDIDATE' for d in result['decisions'])
        replacement=dict(packet,target_ns=target-FIVE_NS,rows=[dict(packet['rows'][0],value=25.)]);store.apply_cohort(replacement)
        new=raw.execute('SELECT version,dirty FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(session,target)).fetchone()
        assert new['dirty'] and new['version']>changed['version']
        checks['F02a_real_peer_consumer_requeued']='PASS'
        store.apply_cohort(dict(replacement,rows=[]))
        row=raw.execute('SELECT * FROM anomaly_detection.adp_peers WHERE service_path=%s AND start_ns=%s',(service,target-FIVE_NS)).fetchone()
        assert row['eligible'] is False and row['value'] is None
        checks['F02b_absent_replacement_not_stale_eligible']='PASS'
        _,epoch=peer_model(store,service,target)
        independent='d'*64
        raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns) VALUES(%s,%s)',(independent,target))
        pending=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s',(independent,)).fetchone())
        store.apply_cohort(replacement)
        assert store.complete(pending,dict(context,peer_inputs={service:epoch}),[],source['captured_at_ns'])['status']=='INPUT_CHANGED_RETRY'
        checks['peer_input_CAS_before_first_dependency_commit']='PASS'
        current=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s',(independent,)).fetchone())
        _,inputs=store.service_details(current,[service])
        assert store.complete(current,dict(context,peer_inputs=inputs),[],source['captured_at_ns'])['status']=='APPLIED'
        with store.transaction():context_changed(store,service,target-FIVE_NS)
        assert raw.execute('SELECT dirty FROM anomaly_detection.adp_jobs WHERE session_key=%s',(independent,)).fetchone()['dirty']
        checks['cross_session_context_input_requeued']='PASS'
        # A family-wide abstention must not silently withdraw an older,
        # service-specific finding in an otherwise covered target window.
        store.invalidate(independent,target)
        current=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s',(independent,)).fetchone())
        candidate={'finding_key':'pf1:'+key(900001),'family':'payment_result_change','dimension':'context','status':'CANDIDATE',
            'reason':'synthetic','score':1,'service_path':service}
        store.complete(current,dict(context,peer_inputs={}),[candidate],source['captured_at_ns'])
        store.invalidate(independent,target)
        current=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s',(independent,)).fetchone())
        cold=dict(candidate,finding_key='pf1:'+key(900002),service_path='*',status='INSUFFICIENT_DATA')
        store.complete(current,dict(context,peer_inputs={}),[cold],source['captured_at_ns'])
        assert raw.execute('SELECT state FROM anomaly_detection.adp_findings WHERE finding_key=%s',(candidate['finding_key'],)).fetchone()['state']=='DEFERRED'
        checks['family_abstention_defers_previous_service_finding']='PASS'
        with tempfile.TemporaryDirectory() as temporary:
            project=Path(temporary)
            with patch('psycopg.connect',side_effect=engine.connect),patch('anomaly_detection.product_source.installed_source_identity',return_value={'runtime_sha256':SOURCE_SHA}), \
                 patch('anomaly_detection.native_pg.source_parameters',return_value={'dbname':'p24_design_viewer','user':'postgres'}):
                reader=ProductSource(project);reader.page_size=1
                cursor_name='test_window';store.save_state(cursor_name,{'target_ns':START+FIVE_NS})
                packet=read_window(reader,store.state(cursor_name));assert packet['has_more']
                assert apply_window(store,packet,cursor_name=cursor_name)['status']=='READING'
                assert owned_context(store,{'session_key':SESSION_A,'target_ns':START+FIVE_NS}) is None
                raw.execute('UPDATE public.viewer_live_state SET generation=12');raw.execute('UPDATE public.viewer_semantic_checkpoint SET generation=12')
                packet=read_window(reader,store.state(cursor_name));assert packet['restart']
                assert apply_window(store,packet,cursor_name=cursor_name)['status']=='RESTART_SNAPSHOT'
                assert store.state(cursor_name).get('after') is None
                checks['partial_window_and_snapshot_restart_not_complete']='PASS'
                for _ in range(12):
                    packet=read_window(reader,store.state(cursor_name));result=apply_window(store,packet,cursor_name=cursor_name)
                    if result['status']=='COMPLETE':break
                assert result['status']=='COMPLETE' and result['behaviors']==5
                current_job=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION_A,START+FIVE_NS)).fetchone())
                local=owned_context(store,current_job);assert local and local['target_complete']
                counts=next(w['counts'] for w in local['windows'] if w['start_ns']==START+FIVE_NS)
                assert counts['Core.v1/UserWalletCharge']==1 and counts['Core.v1/UserProfileUpdate']==1
                assert 'Services.v1/AddUserData' not in counts and 'Core.v1/WalletPayment' not in counts
                checks['all_canonical_kinds_and_no_technical_double_count']='PASS'
                before=store.report()['semantic_changes'];reader.page_size=512
                for _ in range(2):
                    store.save_state('replay',{'target_ns':START+FIVE_NS});apply_window(store,read_window(reader,store.state('replay')),cursor_name='replay')
                assert store.report()['semantic_changes']==before
                checks['window_replay_deduplicated']='PASS'
                old_proof=dict(raw.execute('SELECT * FROM anomaly_detection.adp_source_windows WHERE start_ns=%s',(START+FIVE_NS,)).fetchone())
                raw.execute('UPDATE public.viewer_live_state SET generation=13');raw.execute('UPDATE public.viewer_semantic_checkpoint SET generation=13')
                store.save_state('failed_window',{'target_ns':START+FIVE_NS});packet=read_window(reader,store.state('failed_window'))
                with patch.object(store,'apply_cohort',side_effect=RuntimeError('synthetic rollback')):
                    try:apply_window(store,packet,cursor_name='failed_window')
                    except RuntimeError:pass
                    else:raise AssertionError('fault did not roll back')
                assert dict(raw.execute('SELECT * FROM anomaly_detection.adp_source_windows WHERE start_ns=%s',(START+FIVE_NS,)).fetchone())==old_proof
                assert store.state('failed_window')=={'target_ns':START+FIVE_NS}
                checks['window_cursor_summaries_and_cohort_atomic_rollback']='PASS'
                viewer=os.environ.get('AD_VIEWER_PROJECT')
                if viewer:
                    from anomaly_detection.viewer_bridge import read_journey,reader as bridge_reader
                    reader.project=Path(viewer)
                    bridge=read_journey(reader,key(1))
                    assert bridge['journey'] and bridge['journey']['entry_request_key']==key(1)
                    assert bridge['manual_actions']=='NOT_INFERRED' and bridge['financial_finality']=='NOT_INFERRED'
                    with reader.snapshot() as q:
                        facade=bridge_reader(viewer,q)
                        try:facade.all('UPDATE viewer_requests SET conflicted=1')
                        except ContractError:pass
                        else:raise AssertionError('non SELECT accepted')
                    assert 'sqlite3' not in sys.modules
                    checks['pinned_viewer_delegation_no_init_no_sqlite_select_only']='PASS'
                    from p24_foundation.payment_correlation import correlation_facts,EMITTERS
                    from p24_foundation.viewer_contract import typed_id
                    sequence=30000
                    def correlation(req,label,payload):
                        nonlocal sequence
                        sequence+=1;origin=key(sequence);version=key(sequence+100000);at=START+10_000_000_000
                        call=EMITTERS[label][0]+' Line:1'
                        facts=correlation_facts({'CallPath':call,'message':'correlation: '+label+'\n'+json.dumps(payload)})
                        insert('viewer_events',{'origin_key':origin,'version_key':version,'request_key':req,'at_ns':at,'callpath':call})
                        for issuer,kind,scope,path,value in facts['identifiers']:
                            insert('viewer_contract_identifiers',{'origin_key':origin,'version_key':version,'request_key':req,'issuer':issuer,'kind':kind,
                                'scope':scope,'field_path':path,'identity_key':typed_id(issuer,kind,value,scope=scope),'raw_value':value})
                        for relation,from_kind,from_value,to_kind,to_value,path in facts['edges']:
                            insert('viewer_contract_edges',{'edge_key':key(sequence+500000),'relation_type':relation,
                                'from_typed_id':typed_id('pishkhan24',from_kind,from_value),'to_typed_id':typed_id('pishkhan24',to_kind,to_value),
                                'scope':'core_explicit_correlation','evidence_origin':origin,'evidence_version':version,'evidence_path':path,
                                'request_key':req,'eligibility':'explicit_correlation','confidence':'A','rule_version':'source-synthetic','observed_ns':at})
                        for axis,value,path in facts['states']:
                            insert('viewer_contract_observations',{'origin_key':origin,'version_key':version,'request_key':req,'at_ns':at,
                                'callpath':call,'axis':axis,'value':value,'field_path':path,'authority':'reported'})
                    def root(number,api,session=SESSION_A,category='business'):
                        req=key(number)
                        insert('viewer_requests',{'request_key':req,'session_key':session,'root_call':api,'root_count':1,'conflicted':0,
                            'identity_state':'assigned' if session else 'missing','started_ns':START+1,'ended_ns':START+2})
                        insert('viewer_actions',{'action_key':req,'root_request_key':req,'category':category,'initiation':'unknown'})
                        return req
                    free=root(10001,'Public.v1/ExchangeCurrency')
                    assert read_journey(reader,free)['payment'] is None
                    for scenario,(api,fee,bills) in enumerate([('Services.v1/WaterBills',False,True),
                        ('Services.v1/PostPackagesStatus',True,False),('Services.v1/TrafficFinesCarNoDetails',True,True)],1):
                        req=root(10010+scenario,api);invoice=f'{scenario+100:032x}';bill=f'{scenario+200:032x}'
                        fee_id=f'{scenario+300:032x}';pay_id=f'{scenario+400:032x}'
                        correlation(req,'InvoiceID-BillUniqueIDs',{'InvoiceID':invoice,'BillUniqueIDs':[bill] if bills else []})
                        if fee:
                            fee_req=root(11010+scenario,'Core.v1/InvoicePayment',category='support')
                            correlation(fee_req,'InvoiceID-PaymentKey',{'InvoiceID':invoice,'PaymentKey':fee_id})
                            callback=root(12010+scenario,'Core.v1/PaymentCallback',session=None,category='support')
                            correlation(callback,'PaymentKey-Status',{'PaymentKey':fee_id,'Status':'Success'})
                        if bills:
                            pay_req=root(13010+scenario,'Core.v1/BillsPayment',category='support')
                            correlation(pay_req,'BillUniqueIDs-PaymentKey',{'BillUniqueIDs':[bill],'PaymentKey':pay_id})
                            callback=root(14010+scenario,'Core.v1/PaymentCallback',session=None,category='support')
                            correlation(callback,'PaymentKey-Status',{'PaymentKey':pay_id,'Status':'Failed' if fee else 'Success'})
                        group=read_journey(reader,req)['payment']['invoices'][0]
                        assert len(group['inquiry_payments'])==int(fee) and len(group['bills'])==int(bills)
                        assert len(group['bill_payments'])==int(bills)
                        if fee:assert group['inquiry_payments'][0]['outcome']=='success'
                        if bills:assert group['bill_payments'][0]['outcome']==('failed' if fee else 'success')
                        reverse=read_journey(reader,callback)['payment']['invoices'][0]
                        assert reverse['sources']==group['sources']
                    assert 'sqlite3' not in sys.modules
                    checks['four_inquiry_fee_bill_payment_scenarios_and_sessionless_callback']='PASS'
                else:checks['pinned_viewer_delegation_no_init_no_sqlite_select_only']='NOT_RUN_NO_VIEWER_PROJECT'
                unknown='e'*64;unknown_key=key(60001)
                insert('viewer_requests',{'request_key':unknown_key,'session_key':unknown,'identity_state':'assigned','conflicted':0,'root_call':None})
                insert('viewer_semantic_occurrences',{'request_key':unknown_key,'anchor_key':'ba1:'+key(60002),'session_key':unknown,
                    'anchor_ns':START+FIVE_NS+1,'kind':'product_reservation_execution','root_call':None,'state':'active','revision':1})
                unresolved=reader.context({'session_key':unknown,'target_ns':START+FIVE_NS})
                current=next(w for w in unresolved['windows'] if w['start_ns']==START+FIVE_NS)
                assert current['unmapped_behaviors']==1 and current['counts']=={}
                from anomaly_detection.product_models import evaluate
                assert {d['status'] for d in evaluate(unresolved,[])}=={'INSUFFICIENT_DATA'}
                checks['unmapped_root_survives_source_projection_without_false_normal']='PASS'
                raw.execute('CREATE TABLE public.viewer_retention_audit(audit_id TEXT,cutoff_ns BIGINT,applied_at TEXT,report_json TEXT)')
                raw.execute('INSERT INTO public.viewer_retention_audit VALUES(%s,%s,%s,%s)',('synthetic',START+2*FIVE_NS,'synthetic','{}'))
                raw.execute('DELETE FROM public.viewer_semantic_occurrences WHERE session_key=%s',(SESSION_A,))
                raw.execute('UPDATE public.viewer_live_state SET generation=14');raw.execute('UPDATE public.viewer_semantic_checkpoint SET generation=14')
                after=reader.context({'session_key':SESSION_A,'target_ns':START+FIVE_NS})
                row=next(w for w in after['windows'] if w['start_ns']==START+FIVE_NS)
                assert row['counts'] is None and not row['population_complete'] and row['quality_reason']=='RETENTION_SCOPE_UNAVAILABLE'
                from anomaly_detection.product_models import evaluate
                assert {d['status'] for d in evaluate(after,[])}=={'INSUFFICIENT_DATA'}
                checks['F01_retention_never_becomes_verified_zero_or_benign']='PASS'
        report={'build_id':BUILD_ID,'environment':'POSTGRESQL_WASM_ISOLATED','owner_connections':0,'native_windows_postgresql':'NOT_RUN',
            'checks':checks,'status':'PASS_TARGETED_REGRESSION_NOT_NATIVE_ACCEPTANCE'}
        (ROOT/'validation/PRODUCT_revision06.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()

if __name__=='__main__':main()
