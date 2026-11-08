"""Dense historical progress, input-driven rechecks and stable evidence priority.

Isolated PostgreSQL/WASM; no owner connection or native capacity claim.
"""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import json

from transport import Engine
from check_revision10 import packet,metadata,TARGET,SESSION,SERVICES
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import read_window,apply_window,read_window_burst,owned_context
from anomaly_detection.source_scheduling import WindowContinuations
from anomaly_detection.product_dependencies import context_changed
from anomaly_detection.product_priority import refresh,next_evidence_job
from anomaly_detection.product_engine import evaluate_job
from anomaly_detection.snapshot import canonical

ROOT=Path(__file__).resolve().parents[2]


def main():
    engine=Engine();checks={}
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
        for index,lane in enumerate(('learning_cursor','older_learning_cursor','overlap_cursor','scope_repair_cursor')):
            at=TARGET+index*FIVE_NS;rows=packet(at,{SERVICES[0]:24},offset=100000+index*1000)['rows']
            class Source:
                page_size=2
                generation=1000+index*100
                @contextmanager
                def snapshot(self):yield self.query
                def metadata(self,q):return dict(metadata(at),generation=self.generation,semantic_generation=self.generation)
                def query(self,sql,args=(),**kwargs):
                    if 'viewer_live_windows' in sql:
                        return [{'start_ns':at,'end_ns':at+FIVE_NS,'generation':1,'last_publish_ns':1}]
                    after=args[2] if len(args)>3 else -1
                    return [r for r in rows if r['anchor_ns']>after][:self.page_size+1]
            source=Source();store.save_state(lane,{'target_ns':at})
            # Old schedule: one page per distant source turn/publication.
            for _ in range(8):
                result=apply_window(store,read_window(source,store.state(lane)),cursor_name=lane)
                source.generation+=1
            assert result['status']=='RESTART_SNAPSHOT'
            assert not raw.execute('SELECT complete FROM anomaly_detection.adp_source_windows WHERE start_ns=%s',(at,)).fetchone()
            work=WindowContinuations();groups=[]
            for turn in range(4):
                if turn:assert work.take()==lane
                group=read_window_burst(source,store,clock=SimpleNamespace(monotonic=lambda:0),cursor_name=lane)
                assert len(group)<=4;groups.append(group);work.notice(lane,group[-1])
                if group[-1]['status']=='COMPLETE':break
            assert groups[-1][-1]['status']=='COMPLETE'
            assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_window_members WHERE start_ns=%s',(at,)).fetchone()['n']==24
            checks[lane+'_dense_window_restarts_reproduced_then_finishes_with_full_fence']='PASS'

        # A clean fixed-target decision cannot acquire work or a new version
        # merely because 10 minutes (or a day) elapsed.
        for i in range(500):
            raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,dirty,last_evaluated_ns,processed_version) '
                'VALUES(%s,%s,FALSE,1,1)',(f'{i+50000:064x}',TARGET))
        raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=FALSE,processed_version=version,last_evaluated_ns=1,due_ns=0')
        before=raw.execute('SELECT SUM(version) AS n FROM anomaly_detection.adp_jobs').fetchone()['n']
        for _ in range(64):assert store.next_job(TARGET+288*FIVE_NS,recheck=True) is None
        assert raw.execute('SELECT SUM(version) AS n FROM anomaly_detection.adp_jobs').fetchone()['n']==before
        checks['unchanged_clean_jobs_do_not_repeat_evaluation_on_a_timer']='PASS_500_JOBS_64_TURNS'

        # Dependency corrections still invalidate all actual consumers. A
        # different dirty incident must not be relabelled by this service.
        target=TARGET+100*FIVE_NS
        for session,dirty,state in (('a'*64,False,'NEEDS_REVIEW'),('b'*64,False,'NEEDS_REVIEW'),('c'*64,True,'HOLD')):
            raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,dirty,last_evaluated_ns,processed_version) VALUES(%s,%s,%s,1,1)',(session,target,dirty))
            raw.execute('INSERT INTO anomaly_detection.adp_incidents VALUES(%s,%s,%s,%s,1,%s,%s,1)',('fixture:'+session,session,target,state,'{}','fixture'))
        raw.execute('INSERT INTO anomaly_detection.adp_peer_dependencies VALUES(%s,%s,%s,%s,0)',('a'*64,target,'context:'+SERVICES[2],TARGET))
        raw.execute('INSERT INTO anomaly_detection.adp_peer_dependencies VALUES(%s,%s,%s,%s,0)',('b'*64,target,'context:'+SERVICES[1],TARGET))
        with store.transaction():context_changed(store,SERVICES[2],TARGET+FIVE_NS)
        cases={r['session_key']:r['state'] for r in raw.execute('SELECT session_key,state FROM anomaly_detection.adp_incidents').fetchall()}
        assert cases['a'*64]=='RECHECK_REQUIRED' and cases['b'*64]=='NEEDS_REVIEW' and cases['c'*64]=='HOLD'
        assert store.next_job(TARGET+200*FIVE_NS,recheck=True) is not None
        checks['real_dependency_change_requeues_its_consumers_without_global_incident_relabel']='PASS'

        # Prove the bulk cohort path uses one statement for all consumer case
        # state changes, rather than one query per dependent job.
        service='Services.v1/SyntheticBulk';consumer_target=target+FIVE_NS
        for i in range(200):
            session=f'{i+60000:064x}'
            raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns) VALUES(%s,%s)',(session,consumer_target))
            raw.execute('INSERT INTO anomaly_detection.adp_peer_dependencies VALUES(%s,%s,%s,%s,0)',(session,consumer_target,service,TARGET))
        calls=[];query=engine.query
        def traced(role,sql,args):
            if 'UPDATE anomaly_detection.adp_incidents' in sql:calls.append(sql)
            return query(role,sql,args)
        engine.query=traced
        try:store.apply_cohort({'target_ns':TARGET,'source':metadata(TARGET),'owned_snapshot':True,'available':True,
            'rows':[{'service_path':service,'value':2.,'sessions':30,'population_valid':1}]},advance=False)
        finally:engine.query=query
        assert len(calls)==1
        checks['cohort_case_rechecks_use_one_bulk_statement_for_200_consumers']='PASS'

        # Verified target evidence stays eligible for a queue turn if an old
        # reference/history changes later; it is cleared on its own revision.
        session='e'*64;p=packet(TARGET,{SERVICES[0]:2},session=session,offset=500000)
        p['source']=dict(p['source'],generation=10000,semantic_generation=10000)
        apply_window(store,p)
        for row in p['rows']:
            detail={'source_present':True,'semantic':row,'quality':{'evidence_available':True}}
            raw.execute('UPDATE anomaly_detection.adp_facts SET details=%s,last_audit_ns=1 WHERE request_key=%s',(canonical(detail),row['request_key']))
        refresh(store,[(session,TARGET)],TARGET+200*FIVE_NS)
        job=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(session,TARGET)).fetchone())
        assert job['target_evidence_ready']
        store.complete(job,{'source':p['source'],'peer_inputs':{}},[],TARGET+200*FIVE_NS)
        store.invalidate(session,TARGET-FIVE_NS)
        ready=raw.execute('SELECT target_evidence_ready,dirty FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(session,TARGET)).fetchone()
        assert ready['target_evidence_ready'] and ready['dirty']
        candidates=[]
        for _ in range(10):
            found=next_evidence_job(store,TARGET+300*FIVE_NS)
            if found and found['session_key']==session:break
            if found:raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=FALSE WHERE session_key=%s AND target_ns=%s',(found['session_key'],found['target_ns']))
        assert found and found['session_key']==session
        changed=dict(p['rows'][0],revision=2);store.apply_rows([changed],p['source'])
        assert not raw.execute('SELECT target_evidence_ready FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(session,TARGET)).fetchone()['target_evidence_ready']
        checks['evidence_priority_survives_history_recheck_but_not_target_revision_change']='PASS'

        # Adequate reference plus an ordinary singleton does not become a
        # positive merely because the evidence/queue schedule was changed.
        at=TARGET+500*FIVE_NS;normal='f'*64;service=SERVICES[1]
        for i in range(300):
            raw.execute('INSERT INTO anomaly_detection.adp_service_reference_points VALUES(%s,%s,%s,%s,%s,TRUE)',
                (service,'service_execution',f'{i+80000:064x}',at-(i+1)*2*FIVE_NS,1+i%2))
        current=packet(at,{service:1},session=normal,offset=700000);current['source']=dict(current['source'],generation=10000,semantic_generation=10000)
        apply_window(store,current)
        job=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(normal,at)).fetchone())
        context=store.save_context(job,owned_context(store,job));job['version']=context['job_version']
        result=evaluate_job(store,job,context,at+FIVE_NS)
        decision=next(d for d in result['decisions'] if d['family']=='peer_service_rate_5m')
        assert decision['status']=='NO_DEVIATION_OBSERVED' and decision['peer_session_epochs']>=100
        assert not raw.execute('SELECT 1 FROM anomaly_detection.adp_incidents WHERE session_key=%s AND target_ns=%s',(normal,at)).fetchone()
        checks['adequate_reference_singleton_negative_control_is_not_forced_into_a_case']='PASS_SYNTHETIC_CONTROL'

        report={'build_id':BUILD_ID,'status':'PASS_ISOLATED_POSTGRESQL_WASM','checks':checks,
            'owner_database_or_viewer_modified':False,'native_windows':'NOT_RUN','native_latency_and_capacity':'NOT_MEASURED',
            'detector_criterion':'UNCHANGED_FROM_RELEASE11','native_release12_case_acceptance':'PENDING_OWNER_INSTALL'}
        (ROOT/'validation/PRODUCT_revision12.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()


if __name__=='__main__':main()
