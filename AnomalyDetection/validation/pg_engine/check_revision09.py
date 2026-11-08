"""Pooled-reference and single-family evidence gates on isolated PostgreSQL.

The real export is a root-rate experiment, not a full canonical native replay.
Native Windows PG17 outcomes, latency, precision and recall remain NOT_RUN.
"""
from pathlib import Path
from collections import Counter
import argparse,gzip,hashlib,json,zipfile
from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.service_reference import qualify_roots,import_roots,reference,model,decisions,bootstrap,case_report
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window,owned_context
from anomaly_detection.product_engine import evaluate_job
from anomaly_detection.snapshot import canonical,digest

ROOT=Path(__file__).resolve().parents[2]
SERVICE='Public.v1/ExchangeCrypto'
def token(kind,value):return digest([kind,value])

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root-census',type=Path);parser.add_argument('--viewer-project',type=Path);args=parser.parse_args()
    checks={};engine=Engine()
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
        target=1_800_000_000_000_000_000//FIVE_NS*FIVE_NS
        points=[{'session_key':f'{i+1000:064x}','start_ns':target-(i+1)*3*FIVE_NS,'value':1+i%3} for i in range(120)]
        packet={'dataset_id':'hr1:fixture','service_path':SERVICE,'begin_ns':target-600*FIVE_NS,'cutoff_ns':target,
                'calls':[],'cases':[],'qualification':{'unit':'observed_direct_client_request_roots'}}
        for i,p in enumerate(points):
            for j in range(p['value']):packet['calls'].append({'request_key':f'{10000+i*10+j:064x}',
                'session_key':p['session_key'],'at_ns':p['start_ns']+j,'origin':'synthetic-origin'})
        import_roots(store,packet,target+FIVE_NS)
        session='a'*64
        def window(at,n,offset):
            return {'target_ns':at,'stamp':str(at),'available':True,'has_more':False,'after':None,
                'rows':[{'request_key':f'{offset+i:064x}','anchor_key':'ba1:'+f'{offset+i+100000:064x}',
                    'session_key':session,'anchor_ns':at+i+1,'kind':'service_execution','state':'active','revision':1,
                    'root_call':SERVICE,'root_code':'G00000','identity_state':'assigned','conflicted':False,'request_session_key':session} for i in range(n)],
                'source':{'namespace':'viewer:test','stream_key':'test','keys_fingerprint':'test','generation':2,'semantic_generation':2,
                    'captured_at_ns':at+FIVE_NS,'next_ns':at+FIVE_NS}}
        def evaluate(at):
            job=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(session,at)).fetchone())
            context=store.save_context(job,owned_context(store,job));job['version']=context['job_version']
            return evaluate_job(store,job,context,target+1000*FIVE_NS)
        def qualify(at,available=True,transport=SERVICE):
            for row in raw.execute('SELECT request_key,body FROM anomaly_detection.adp_facts WHERE session_key=%s AND at_ns>=%s AND at_ns<%s',(session,at,at+FIVE_NS)).fetchall():
                e=json.loads(row['body']);fact={'source_present':True,'semantic':e,'quality':{'evidence_available':available},
                    'transport':{'root_call':transport},'observations':[],'identifiers':[],'relations':[],
                    'evidence':[{'origin_key':digest(['origin',row['request_key']]),'version_key':digest(['version',row['request_key']]),
                                 'callpath':SERVICE,'at_ns':e['anchor_ns'],'qualified':available,'raw_available':available}]}
                raw.execute('UPDATE anomaly_detection.adp_facts SET details=%s,details_digest=%s WHERE request_key=%s',
                            (canonical(fact),digest(fact),row['request_key']))
            store.invalidate(session,at)
        apply_window(store,window(target,50,1));evaluate(target)
        assert raw.execute('SELECT state FROM anomaly_detection.adp_incidents WHERE session_key=%s AND target_ns=%s',(session,target)).fetchone()['state']=='HOLD'
        checks['missing_request_evidence_does_not_promote_a_strong_rate']='PASS'
        qualify(target);evaluate(target)
        case=raw.execute('SELECT state,body FROM anomaly_detection.adp_incidents WHERE session_key=%s AND target_ns=%s',(session,target)).fetchone()
        assert case['state']=='NEEDS_REVIEW';assert json.loads(case['body'])['signal_groups']==1
        checks['one_qualified_reference_detector_can_require_review_without_second_dimension']='PASS'
        second=target+8*FIVE_NS;apply_window(store,window(second,40,100));qualify(second);evaluate(second)
        assert raw.execute('SELECT state FROM anomaly_detection.adp_incidents WHERE session_key=%s AND target_ns=%s',(session,second)).fetchone()['state']=='NEEDS_REVIEW'
        checks['fifty_and_forty_with_same_frozen_past_reference_both_require_review']='PASS_SYNTHETIC_CANONICAL_INPUTS'
        qualify(second,transport='Services.v1/InvoiceRegister');evaluate(second)
        assert raw.execute('SELECT state FROM anomaly_detection.adp_incidents WHERE session_key=%s AND target_ns=%s',(session,second)).fetchone()['state']!='NEEDS_REVIEW'
        checks['raw_http_reference_cannot_be_used_for_dispatcher_transport']='PASS'
        qualify(target,available=False);evaluate(target)
        assert raw.execute('SELECT state FROM anomaly_detection.adp_incidents WHERE session_key=%s AND target_ns=%s',(session,target)).fetchone()['state']!='NEEDS_REVIEW'
        checks['loss_of_current_origin_evidence_demotes_previous_case']='PASS'
        # Stale first-consumer epoch cannot commit even without a previous dependency.
        j=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(session,target)).fetchone())
        ctx=store.save_context(j,owned_context(store,j));j['version']=ctx['job_version']
        ref,epochs=model(store,SERVICE,session,target,'service_execution')
        raw.execute('UPDATE anomaly_detection.adp_peer_epochs SET version=version+1 WHERE service_path=%s',('reference:'+SERVICE,))
        assert store.complete(j,dict(ctx,peer_inputs=epochs),[],target+FIVE_NS)['status']=='INPUT_CHANGED_RETRY'
        checks['reference_epoch_cas_preserves_concurrent_input_changes']='PASS'
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_facts').fetchone()['n']==90
        assert len(store.state('source_binding'))==3
        checks['root_reference_never_creates_canonical_facts_or_source_windows']='PASS'
        # A different API learns automatically from qualified canonical shared
        # windows; there is no ExchangeCrypto/name-specific detector threshold.
        other='Public.v1/OtherQuote'
        for i,p in enumerate(points):
            at=p['start_ns'];w=window(at,p['value'],500000+i*10)
            for item in w['rows']:
                item.update(session_key=p['session_key'],request_session_key=p['session_key'],root_call=other)
            apply_window(store,w)
        learned,_=model(store,other,session,target,'service_execution')
        assert learned['status']=='READY_BASELINE' and learned['unit']=='canonical_service_executions'
        assert learned['other_session_epochs']==120 and learned['upper']==3
        checks['another_service_learns_from_canonical_windows_without_raw_seed']='PASS'
        # Full lookup entry is invalidated by an asynchronous semantic change;
        # a stale point cannot remain qualified while waiting for window replay.
        old=raw.execute('SELECT body FROM anomaly_detection.adp_facts WHERE service_path=%s ORDER BY at_ns LIMIT 1',(other,)).fetchone()
        changed=json.loads(old['body']);changed.update(revision=changed['revision']+1,state='withdrawn')
        store.apply_rows([changed],w['source'])
        tainted=raw.execute('SELECT qualified FROM anomaly_detection.adp_service_reference_points WHERE service_path=%s AND session_key=%s AND start_ns=%s',
            (other,changed['session_key'],changed['anchor_ns']//FIVE_NS*FIVE_NS)).fetchone()
        assert tainted and tainted['qualified'] is False
        checks['late_semantic_change_taints_owned_reference_point_until_full_replay']='PASS'
        retained_at=points[40]['start_ns']
        unavailable=window(retained_at,0,900000)
        unavailable.update(available=False)
        unavailable['source']['retention_cutoff_ns']=retained_at+FIVE_NS
        apply_window(store,unavailable)
        after_prune,_=model(store,other,session,target,'service_execution')
        assert after_prune['status']=='READY_BASELINE' and after_prune['other_session_epochs']==119
        assert after_prune['upper']==3
        checks['known_viewer_retention_preserves_already_qualified_ad_reference']='PASS'
        experiment=None
        if args.root_census:
            with zipfile.ZipFile(args.root_census) as z:meta=json.loads(z.read('manifest.json'));roots=[json.loads(l) for l in gzip.decompress(z.read('service_roots.jsonl.gz')).splitlines()]
            real=qualify_roots(args.root_census,token,meta['source_fingerprint'])
            pooled=Counter((r['session_key'],r['at_ns']//FIVE_NS*FIVE_NS) for r in real['calls'])
            real_points=[{'session_key':s,'start_ns':at,'value':n} for (s,at),n in pooled.items()]
            hold=Counter((token('session',r['_source']['Session']),__import__('anomaly_detection.service_reference',fromlist=['timestamp']).timestamp(r['_source']['@timestamp'])//FIVE_NS*FIVE_NS) for r in roots if r['partition']=='holdout')
            results=[]
            for (s,at),n in hold.items():
                ref=reference(real_points,s,real['cutoff_ns'],SERVICE,unit='observed_direct_client_request_roots',reference_id=real['dataset_id'])
                tail=(1+sum(v>=n for v in ref['reference_values']))/(len(ref['reference_values'])+1)
                results.append({'observed':n,'reference_sessions':ref['other_session_epochs'],'reference_max':ref['upper'],
                                'candidate':ref['status']=='READY_BASELINE' and n>3*ref['upper'] and tail<=.01,'tail_rank':tail})
            assert sorted(r['observed'] for r in results if r['candidate'])==[40,50]
            assert sum(r['observed']==1 and not r['candidate'] for r in results)==6
            assert real['qualification']['holdout_calls_excluded']==96
            experiment={'scope':'REAL_HTTP_ROOT_RATE_EXPERIMENT_NOT_NATIVE_CANONICAL_ACCEPTANCE','historical_calls':len(real['calls']),
                'missing_session_rows_excluded':real['qualification']['missing_session_rows_excluded'],
                'reference_capture_sha256':real['qualification']['raw_reference_sha256'],'results':results,
                'ordinary_holdout_cases_are_not_verified_benign_labels':True,'precision_recall':'NOT_EVALUATED'}
            checks['real_1193_root_census_frozen_reference_finds_50_and_40_not_six_single_calls']='PASS_ROOT_METRIC_ONLY'
        if args.viewer_project:
            import tempfile,sys
            from tests.test_service_reference import CensusQualificationTests
            sys.path.insert(0,str(args.viewer_project))
            from p24_foundation.privacy import Keys
            from anomaly_detection import SOURCE_SHA
            from unittest.mock import patch
            with tempfile.TemporaryDirectory(prefix='reference bootstrap ') as directory:
                project=Path(directory);(project/'AnomalyDetection/reports').mkdir(parents=True)
                (project/'private').mkdir();(project/'p24_foundation').symlink_to(args.viewer_project/'p24_foundation',target_is_directory=True)
                keypath=project/'private/reference keys.json'
                keypath.write_text(json.dumps({'equality':'01'*32,'encryption':'02'*32,'version':'fixture'}))
                keys=Keys.read(keypath);before=hashlib.sha256(keypath.read_bytes()).hexdigest()
                config="HOST='http://fixture.invalid'\nES_INDEX='fixture-*'\nKEYS_PATH: str='private/reference keys.json'\nELASTICSEARCH=dict(host=HOST,index_pattern=ES_INDEX)\nopen('must-not-execute','w').write('bad')\n"
                (project/'viewer_config.local.py').write_text(config)
                fp=hashlib.sha256(json.dumps(['http://fixture.invalid','fixture-*']).encode()).hexdigest()
                path=CensusQualificationTests().archive(project/'AnomalyDetection/reports',mutate_manifest=lambda m:m.update(source_fingerprint=fp))
                path.rename(path.with_name('anomaly_history_v2_fixture.zip'))
                isolated=Engine()
                try:
                    own=isolated.connect();own.execute('CREATE SCHEMA anomaly_detection');reader_store=ProductStore(own);reader_store.initialize()
                    source={'namespace':'viewer:fixture','stream_key':'fixture','keys_fingerprint':keys.fingerprint,'generation':1,
                        'semantic_generation':1,'runtime_sha256':SOURCE_SHA}
                    result=bootstrap(reader_store,project,source)
                    assert result['status']=='IMPORTED_ROOT_RATE_REFERENCE',result
                    assert bootstrap(reader_store,project,source)['status']=='ALREADY_IMPORTED'
                    assert own.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_facts').fetchone()['n']==0
                    first=own.execute('SELECT session_key FROM anomaly_detection.adp_http_reference_calls ORDER BY at_ns LIMIT 1').fetchone()
                    assert first['session_key']==keys.token('p24-viewer.1','session','s0').split(':')[-1]
                    assert hashlib.sha256(keypath.read_bytes()).hexdigest()==before
                    assert not (project/'must-not-execute').exists() and not Path('must-not-execute').exists()
                    assert len(case_report(reader_store)['cases'])==1
                    checks['native_bootstrap_path_literal_config_keys_namespace_and_idempotence']='PASS_ISOLATED_SQL_AND_PINNED_KEYS'
                finally:isolated.close()
        report={'build_id':BUILD_ID,'status':'PASS_REVISION09_OFFLINE','checks':checks,'real_root_experiment':experiment,
            'environment':'ISOLATED_POSTGRESQL_WASM','owner_connections':0,'native_windows_postgresql':'NOT_RUN',
            'native_case_results':'NOT_RUN','native_latency':'NOT_MEASURED','precision_recall':'NOT_EVALUATED'}
        (ROOT/'validation/PRODUCT_revision09.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()

if __name__=='__main__':main()
