"""Content/technical request adapter, stable cases, CAS and read-only UI on PG.

All source tables here are disposable fixtures. No owner connection, no claim
of native Windows latency, production precision or complete financial logs.
"""
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
import json,sys,zlib
from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window
from anomaly_detection.snapshot import canonical,digest
from anomaly_detection.scenario_store import publish_scope,process_one,enqueue,scope_key,save_profile,scope_profiles
from anomaly_detection.case_summary import case_status
from anomaly_detection.cases import identity
from anomaly_detection.product_web import render
from tests.test_scenarios import T,S,point,refs
from check_revision10 import packet,metadata

ROOT=Path(__file__).resolve().parents[2]


def insert_many(raw,table,columns,rows):
    if rows:raw.execute('INSERT INTO anomaly_detection.'+table+'('+','.join(n for n,t in columns)+') SELECT * FROM jsonb_to_recordset(%s::jsonb) AS x('+','.join(n+' '+t for n,t in columns)+')',(canonical(rows),))


def main(reference=None):
    engine=Engine();checks={}
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
        baseline=refs();profiles=[];scopes=[]
        for unit in baseline:
            for p in unit:profiles.append({'request_key':p['request_key'],'session_key':p['session_key'],'service_path':S,'at_ns':p['at_ns'],'body':canonical(p),'content_digest':digest(p),'observed_ns':T-FIVE_NS})
            scopes.append({'session_key':unit[0]['session_key'],'service_path':S,'start_ns':unit[0]['at_ns']//FIVE_NS*FIVE_NS,'request_keys':canonical([p['request_key'] for p in unit]),'independent':True,'available':True,'authority':'canonical'})
        insert_many(raw,'adp_profiles',[('request_key','TEXT'),('session_key','TEXT'),('service_path','TEXT'),('at_ns','BIGINT'),('body','TEXT'),('content_digest','TEXT'),('observed_ns','BIGINT')],profiles)
        insert_many(raw,'adp_profile_scopes',[('session_key','TEXT'),('service_path','TEXT'),('start_ns','BIGINT'),('request_keys','TEXT'),('independent','BOOLEAN'),('available','BOOLEAN'),('authority','TEXT')],scopes)
        actor='c'*64;apply_window(store,packet(T,{S:20},session=actor,offset=50000))
        rows=raw.execute('SELECT * FROM anomaly_detection.adp_facts WHERE session_key=%s ORDER BY at_ns',(actor,)).fetchall();keys=[r['request_key'] for r in rows]
        publish_scope(store,actor,S,T,keys)
        for i,r in enumerate(rows):
            p=point(50000+i,actor,r['at_ns'],topic='same-original-bill',subject='same-original-bill')
            p.update(semantic_active=True,semantic_revision=r['revision'],anchor_key=r['anchor_key'])
            save_profile(store,{'source':metadata(T),'request_key':p['request_key'],'profile':p},T+FIVE_NS)
        result=process_one(store,T+2*FIVE_NS);assert result['status']=='APPLIED',result
        d=next(d for d in result['decisions'] if d['family']=='repeated_target')
        assert d['observed']==20 and d['single_signal_review_eligible'] and d['upper']==1,d
        key=identity('actor',actor,'repeat_target',S);status=case_status(store,key)
        assert status['bucket']=='READY',dict(status)
        case=dict(raw.execute('SELECT * FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone());body=json.loads(case['body']);assert body['distinct_executions']==20
        assert raw.execute('SELECT 1 FROM anomaly_detection.adp_models WHERE model_id=%s',(d['model_id'],)).fetchone()
        checks['same_bill20_is_reviewable_from_content_even_without_a_high_service_call_rate']='PASS_400_COMPARABLE_OTHER_ACTOR_COHORTS'
        enqueue(store,'actor',actor,S,T);replayed=process_one(store,T+3*FIVE_NS)
        again=dict(raw.execute('SELECT * FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone());assert again==case,(case,again)
        checks['replay_preserves_one_case_revision_and_20_unique_requests']='PASS'
        # Currentness changes immediately when a profile's real evidence changes.
        old=json.loads(raw.execute('SELECT body FROM anomaly_detection.adp_profiles WHERE request_key=%s',(keys[0],)).fetchone()['body'])
        late=dict(old,witnesses=[{'at_ns':T+288*FIVE_NS,'origin_key':'late','version_key':'v2'}])
        save_profile(store,{'source':metadata(T),'request_key':keys[0],'profile':late},T+288*FIVE_NS)
        assert case_status(store,key)['bucket']=='RECHECK'
        process_one(store,T+289*FIVE_NS)
        revised=raw.execute('SELECT revision,body FROM anomaly_detection.adp_cases WHERE case_key=%s',(key,)).fetchone()
        assert revised['revision']>case['revision'] and json.loads(revised['body'])['distinct_executions']==20
        assert case_status(store,key)['bucket']=='READY'
        checks['late_evidence_updates_original_case_without_an_extra_execution']='PASS'
        # Inject an input change between model reads and result row lock.
        enqueue(store,'actor',actor,S,T);chosen=scope_key('actor',actor,S,T)
        execute=raw.execute;fired=False
        def interleave(sql,args=()):
            nonlocal fired
            if 'SELECT version FROM anomaly_detection.adp_scenario_jobs' in sql and 'FOR UPDATE' in sql and args==(chosen,) and not fired:
                fired=True;execute('UPDATE anomaly_detection.adp_scenario_jobs SET version=version+1 WHERE scope_key=%s',(chosen,))
            return execute(sql,args)
        with patch.object(raw,'execute',side_effect=interleave):
            for _ in range(12):
                rejected=process_one(store,T+290*FIVE_NS)
                if fired:break
        assert rejected['status']=='INPUT_CHANGED_RETRY' and fired,rejected
        assert case_status(store,key)['bucket']=='RECHECK'
        process_one(store,T+291*FIVE_NS)
        checks['outdated_profile_result_cannot_commit_after_input_version_change']='PASS_INJECTED_INTERLEAVING_NOT_NATIVE_MULTI_CONNECTION_ISOLATION'
        with raw.transaction():
            raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            for path in ('/scenarios','/scenario-evaluation/'+chosen,'/case/'+key):
                html=render(store,{},path,{},'token');assert 'dir="rtl"' in html and 'شاهد' in html
        checks['scenario_summary_decision_drilldown_and_stable_case_render_in_read_only_snapshot']='PASS_HTML'
        def drain(wanted,at):
            for _ in range(80):
                r=raw.execute('SELECT dirty FROM anomaly_detection.adp_scenario_jobs WHERE scope_key=%s',(wanted,)).fetchone()
                if r and not r['dirty']:return
                process_one(store,at)
            raise AssertionError('scenario target did not finish')
        def sampled_window(at,offset,code='G00000',value=False):
            p=packet(at,{},offset=offset);p['rows']=[]
            actors=[f'{8000+i:064x}' for i in range(5)]
            for i,a in enumerate(actors):p['rows']+=packet(at,{S:4},session=a,offset=offset+i*100)['rows']
            apply_window(store,p)
            for i,a in enumerate(actors):
                rs=raw.execute('SELECT * FROM anomaly_detection.adp_facts WHERE session_key=%s AND at_ns>=%s AND at_ns<%s ORDER BY at_ns',(a,at,at+FIVE_NS)).fetchall()
                publish_scope(store,a,S,at,[r['request_key'] for r in rs],independent=True)
                for j,r in enumerate(rs):
                    item=point(offset+i*100+j,a,r['at_ns'],code=code,value=value)
                    item.update(semantic_active=True,semantic_revision=r['revision'],anchor_key=r['anchor_key'])
                    save_profile(store,{'source':metadata(T),'request_key':item['request_key'],'profile':item},at+FIVE_NS)
            wanted=scope_key('response',S,S,at);drain(wanted,at+2*FIVE_NS)
            return wanted
        response_scope=sampled_window(T+2*FIVE_NS,1_000_000)
        content_key=identity('service',S,'response_content',S)
        assert case_status(store,content_key)['bucket']=='READY'
        assert 'تغییر محتوای پاسخ' in render(store,{},'/scenario-evaluation/'+response_scope,{},'token')
        checks['same_schema_negative_result_with_success_code_creates_a_service_content_case']='PASS_FULL_OWNED_SQL_PATH'
        sampled_window(T+3*FIVE_NS,1_100_000,code='GD9999')
        health=identity('service',S,'service_health',S)
        assert case_status(store,health)['bucket']=='READY'
        sampled_window(T+4*FIVE_NS,1_200_000,code='GD9999')
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_cases WHERE case_key=%s',(health,)).fetchone()['n']==1
        hb=json.loads(raw.execute('SELECT body FROM anomaly_detection.adp_cases WHERE case_key=%s',(health,)).fetchone()['body'])
        assert hb['distinct_executions']==40 and hb['active_signals']==2,hb
        checks['repeated_service_failure_windows_update_one_health_case_with_40_unique_requests']='PASS'
        volume_service='Services.v1/VolumeControl';at=T+10*FIVE_NS
        for i in range(200):
            body={'start_ns':at-(i+1)*FIVE_NS,'executions':100,'sessions':5,'covered':True}
            raw.execute('INSERT INTO anomaly_detection.adp_population VALUES(%s,%s,%s,%s)',(volume_service,body['start_ns'],canonical(body),digest(body)))
        body={'start_ns':at,'executions':0,'sessions':0,'covered':True}
        raw.execute('INSERT INTO anomaly_detection.adp_population VALUES(%s,%s,%s,%s)',(volume_service,at,canonical(body),digest(body)))
        enqueue(store,'canonical_traffic',volume_service,volume_service,at);drain(scope_key('canonical_traffic',volume_service,volume_service,at),at+FIVE_NS)
        volume_key=identity('service',volume_service,'service_volume',volume_service)
        assert case_status(store,volume_key)['bucket']=='READY'
        assert 'کاهش' in render(store,{},'/case/'+volume_key,{},'token')
        checks['fully_covered_zero_traffic_decrease_is_a_renderable_case_without_fabricated_requests']='PASS'
        # Source adapter: use the actual pinned parser and RawEvidenceMixin.
        reference=Path(reference).resolve() if reference else ROOT.parent
        from anomaly_detection.pg_source import installed_source_identity
        source_identity=installed_source_identity(reference)
        assert source_identity['checked_runtime_files']>0
        checks['source_adapter_fixture_uses_a_fully_digest_verified_pinned_runtime']=f"PASS_{source_identity['checked_runtime_files']}_FILES"
        schema=json.loads((ROOT/'reference/handoff_20261031/reference/viewer_schema_reference.json').read_text())['tables']
        for name in ('viewer_requests','viewer_semantic_occurrences','viewer_events','viewer_raw_events','viewer_links','viewer_contract_observations','viewer_live_windows'):
            spec=schema[name];columns=[]
            for c in spec['columns']:
                typ={'INTEGER':'BIGINT','BLOB':'BYTEA','REAL':'DOUBLE PRECISION'}.get(c['declared_type'],c['declared_type']);columns.append('"'+c['name']+'" '+typ)
            raw.execute('CREATE TABLE public.'+name+'('+','.join(columns)+')')
        def add(name,row):
            expressions=["decode(%s,'hex')" if isinstance(v,bytes) else '%s' for v in row.values()]
            values=tuple(v.hex() if isinstance(v,bytes) else v for v in row.values())
            raw.execute('INSERT INTO public.'+name+'('+','.join(row)+') VALUES('+','.join(expressions)+')',values)
        owner='a'*64
        for i,root in enumerate((S,S,'Core.v1/DeviceRegister',S)):
            rk=f'{900000+i:064x}';origin=f'{910000+i:064x}';version=f'{920000+i:064x}'
            message='Input: '+json.dumps([{'ElectricityBillID':'001234','TraceNumber':str(i),'Token':'do-not-store'}] if i<2 else [{'DeviceID':'device-one','TraceNumber':str(i)}])+' Output: '+json.dumps([{'Parameters':{'HasRecord':False},'Status':{'Code':'G00000'}}])
            who=owner if i<3 else None
            add('viewer_requests',{'request_key':rk,'session_key':who,'identity_state':'assigned' if who else 'missing','conflicted':0,'root_ns':T+10+i,'started_ns':T+10+i,'ended_ns':T+20+i,'root_call':root,'root_code':'G00000','root_count':1})
            add('viewer_events',{'request_key':rk,'session_key':who,'origin_key':origin,'version_key':version,'at_ns':T+10+i,'ip_key':f'client-ip-{i}','kind':'client','callpath':root})
            add('viewer_raw_events',{'origin_key':origin,'version_key':version,'raw_ip':'192.0.2.'+str(i+1),'payload':zlib.compress(json.dumps({'message':message}).encode())})
        add('viewer_live_windows',{'start_ns':T,'end_ns':T+FIVE_NS,'generation':100,'last_publish_ns':T+FIVE_NS})
        class Source:
            project=reference
            @contextmanager
            def snapshot(self):
                with raw.transaction():
                    raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                    def q(sql,args=(),*,cap=4000):
                        assert sql.lstrip().startswith('SELECT ')
                        rows=raw.execute(sql+' LIMIT %s',(*args,cap+1)).fetchall();assert len(rows)<=cap
                        return rows
                    yield q
            def metadata(self,q):return metadata(T)
        from anomaly_detection.request_profiles import read
        source=Source();a=read(source,f'{900000:064x}');b=read(source,f'{900001:064x}');device=read(source,f'{900002:064x}')
        assert a['profile']['qualified'] and a['profile']['targets']==b['profile']['targets']
        assert a['profile']['ip_keys']!=b['profile']['ip_keys']
        assert a['profile']['ip_display']=={'client-ip-0':'192.0.2.1'} and b['profile']['ip_display']=={'client-ip-1':'192.0.2.2'}
        assert 'do-not-store' not in canonical(a['profile']) and '001234' not in canonical(a['profile'])
        assert device['profile']['qualified'] and device['profile']['service_path']=='Core.v1/DeviceRegister' and not device['profile']['semantic_active']
        assert 'sqlite3' not in sys.modules
        checks['actual_viewer_raw_reader_and_parser_keep_same_bill_despite_trace_and_ip_changes']='PASS_DISPOSABLE_PG_SOURCE_FIXTURE'
        checks['technical_registration_request_profile_does_not_require_a_business_anchor_or_load_sqlite']='PASS'
        anonymous=read(source,f'{900003:064x}')
        assert anonymous['profile']['qualified'] and not anonymous['profile']['actor_qualified'] and anonymous['profile']['session_key'] is None
        save_profile(store,anonymous,T+FIVE_NS)
        from anomaly_detection.scenario_traffic import read_page,apply
        before=raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_facts').fetchone()['n']
        census=read_page(source,{'target_ns':T});assert census['status']=='PAGE' and len(census['rows'])==4,census
        part=dict(census,rows=census['rows'][:1],has_more=True,after=[T+10,census['rows'][0]['origin_key']])
        assert apply(store,part,cursor_name='fixture-lane')=='PAGE'
        assert not raw.execute('SELECT 1 FROM anomaly_detection.adp_traffic_counts').fetchone()
        assert apply(store,dict(census,status='RESTART'),cursor_name='fixture-lane')=='RESTART'
        assert apply(store,census,cursor_name='fixture-lane')=='COMPLETE'
        count=json.loads(raw.execute('SELECT body FROM anomaly_detection.adp_traffic_counts WHERE service_path=%s',('Core.v1/DeviceRegister',)).fetchone()['body'])
        assert count['requests']==1 and count['sessions']==1 and count['complete']
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_facts').fetchone()['n']==before
        checks['root_request_census_is_atomic_and_technical_calls_do_not_create_semantic_facts']='PASS_FENCE_RESTART_AND_OWNED_QUEUE'
        sample=raw.execute('SELECT request_keys FROM anomaly_detection.adp_service_profile_samples WHERE service_path=%s AND start_ns=%s',(S,T)).fetchone()
        assert f'{900003:064x}' in json.loads(sample['request_keys'])
        assert raw.execute('SELECT 1 FROM anomaly_detection.adp_service_sample_members WHERE request_key=%s',(f'{900003:064x}',)).fetchone()
        # A service workflow case can be supported by qualified anonymous
        # requests; they never become a fictional actor or business behavior.
        workflow_at=T+20*FIVE_NS;anonkeys=[]
        for i in range(10):
            p=point(3_000_000+i,None,workflow_at+i,access=False);p['actor_qualified']=False
            save_profile(store,{'source':metadata(T),'request_key':p['request_key'],'profile':p},workflow_at+FIVE_NS);anonkeys.append(p['request_key'])
        raw.execute('INSERT INTO anomaly_detection.adp_service_profile_samples VALUES(%s,%s,%s,TRUE)',(S,T-2*288*FIVE_NS,canonical([p['request_key'] for p in baseline[0]])))
        # 100 past requests with the learned access step, independent of any
        # anomaly candidate selection, are required for workflow comparison.
        raw.execute('UPDATE anomaly_detection.adp_service_profile_samples SET request_keys=%s WHERE service_path=%s AND start_ns=%s',(canonical([p['request_key'] for unit in baseline[:5] for p in unit]),S,T-2*288*FIVE_NS))
        raw.execute('INSERT INTO anomaly_detection.adp_service_profile_samples VALUES(%s,%s,%s,TRUE)',(S,workflow_at,canonical(anonkeys)))
        enqueue(store,'request_workflow',S,S,workflow_at);drain(scope_key('request_workflow',S,S,workflow_at),workflow_at+FIVE_NS)
        wk=identity('service',S,'workflow',S)
        assert case_status(store,wk)['bucket']=='READY'
        members=raw.execute('SELECT session_key FROM anomaly_detection.adp_case_requests WHERE case_key=%s',(wk,)).fetchall()
        assert len(members)==10 and all(r['session_key'] is None for r in members)
        checks['anonymous_requests_keep_service_workflow_detection_without_inventing_a_user']='PASS_SOURCE_READER_QUEUE_SQL_AND_CASE'
        save_profile(store,device,T+FIVE_NS)
        assert not raw.execute('SELECT 1 FROM anomaly_detection.adp_profile_tasks WHERE request_key=%s',(device['request_key'],)).fetchone()
        raw.execute('UPDATE public.viewer_events SET version_key=%s WHERE request_key=%s',('changed-root-version',device['request_key']))
        raw.execute('UPDATE public.viewer_raw_events SET version_key=%s WHERE origin_key=%s',('changed-root-version',f'{910002:064x}'))
        revised_census=read_page(source,{'target_ns':T});assert apply(store,revised_census,cursor_name='fixture-lane')=='COMPLETE'
        assert raw.execute('SELECT 1 FROM anomaly_detection.adp_profile_tasks WHERE request_key=%s',(device['request_key'],)).fetchone()
        raw.execute('UPDATE public.viewer_requests SET conflicted=1 WHERE request_key=%s',(device['request_key'],))
        assert apply(store,read_page(source,{'target_ns':T}),cursor_name='fixture-lane')=='COMPLETE'
        removed=raw.execute('SELECT request_keys FROM anomaly_detection.adp_profile_scopes WHERE session_key=%s AND service_path=%s AND start_ns=%s',(owner,'Core.v1/DeviceRegister',T)).fetchone()
        assert removed and json.loads(removed['request_keys'])==[]
        assert not scope_profiles(store,owner,'Core.v1/DeviceRegister',T)[1]
        checks['changed_technical_root_requeues_content_and_retracted_owner_scope_is_not_current']='PASS_HISTORICAL_CENSUS_REPLAY'
        report={'build_id':BUILD_ID,'status':'PASS_CONTENT_NETWORK_SCENARIO_PIPELINE_SQL','checks':checks,
            'owner_connections':0,'native_windows_postgresql':'NOT_RUN','production_precision_recall_and_capacity':'NOT_MEASURED','source_modified':False,'financial_acceptance':'BLOCKED_EXTERNAL_EVIDENCE_NOT_INFERRED'}
        (ROOT/'validation/PRODUCT_revision19.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()


if __name__=='__main__':main()
