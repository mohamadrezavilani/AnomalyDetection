"""Ready-pass fairness and visible abstention using an isolated PG/WASM engine."""
from pathlib import Path
import json
from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window,owned_context
from anomaly_detection.product_engine import evaluate_job
from anomaly_detection.product_web import render
from anomaly_detection.snapshot import canonical

ROOT=Path(__file__).resolve().parents[2]
TARGET=1_800_000_000_000_000_000//FIVE_NS*FIVE_NS
SESSION='a'*64;SERVICE='Public.v1/ExchangeCrypto'


def packet(target,n,offset=0):
    return {'target_ns':target,'stamp':'window-'+str(target),'available':True,'has_more':False,'after':None,
            'rows':[{'request_key':f'{i+offset:064x}','anchor_key':'ba1:'+f'{i+offset+10000:064x}',
                     'session_key':SESSION,'anchor_ns':target+(i+1)*1_000_000_000,'kind':'service_execution',
                     'state':'active','revision':1,'root_call':SERVICE,'root_code':'G00000','identity_state':'assigned',
                     'conflicted':0,'request_session_key':SESSION} for i in range(n)],
            'source':{'namespace':'viewer:test','stream_key':'test','keys_fingerprint':'test','generation':2,
                      'semantic_generation':2,'captured_at_ns':target+FIVE_NS,'next_ns':target+FIVE_NS}}


def evaluate(store,target):
    job=dict(store.raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',
                             (SESSION,target)).fetchone())
    context=store.save_context(job,owned_context(store,job));job['version']=context['job_version']
    return evaluate_job(store,job,context,TARGET+100*FIVE_NS)


def main():
    engine=Engine();checks={}
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection')
        store=ProductStore(raw);store.initialize()
        apply_window(store,packet(TARGET,50))
        for i in range(1,8):apply_window(store,packet(TARGET+i*FIVE_NS,0))
        second=TARGET+8*FIVE_NS;apply_window(store,packet(second,40,100))
        evaluate(store,TARGET)
        job=raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION,TARGET)).fetchone()
        saved=json.loads(job['evaluation']);rate=next(v for v in saved['decisions'] if v['family']=='rate_5m')
        assert rate['observed']==50 and rate['status']=='INSUFFICIENT_DATA' and rate['service_path']==SERVICE
        assert rate['personal_history_windows']==0 and rate['peer_qualified_windows']==0
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_incidents').fetchone()['n']==0
        checks['fifty_observed_executions_abstain_without_fabricating_incident']='PASS'
        page=render(store,{},'/evaluation/'+SESSION+'/'+str(TARGET),{},'csrf')
        assert 'دادهٔ ناکافی' in page and '50' in page and SERVICE in page
        assert 'http://127.0.0.1:5021/request/' in page
        checks['native_shape_cold_decision_visible_with_count_and_witness']='PASS_SQL_AND_HTML'
        waiting=raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION,second)).fetchone()
        assert waiting['last_evaluated_ns'] is None and waiting['dirty']
        before=[dict(row) for row in raw.execute('SELECT * FROM anomaly_detection.adp_jobs ORDER BY target_ns,session_key').fetchall()]
        page=render(store,{},'/evaluation/'+SESSION+'/'+str(second),{},'csrf')
        assert '40' in page and 'در صف ارزیابی' in page
        listing=render(store,{},'/evaluations',{'session_key':['http://127.0.0.1:5021/session/'+SESSION+'/behavior']},'csrf')
        assert '/evaluation/'+SESSION+'/'+str(second) in listing
        after=[dict(row) for row in raw.execute('SELECT * FROM anomaly_detection.adp_jobs ORDER BY target_ns,session_key').fetchall()]
        assert before==after
        checks['forty_pending_executions_visible_without_any_write_or_evaluation']='PASS_SQL_AND_HTML'
        # An already evaluated older window may be repeatedly invalidated;
        # the ready lane still selects the never-evaluated 40-request target.
        raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=TRUE WHERE target_ns<%s',(second,))
        chosen=store.next_ready_job(TARGET+1000*FIVE_NS)
        assert chosen['target_ns']==second,chosen
        checks['first_assessment_precedes_repeated_older_rechecks']='PASS'
        # Restart before completion must not drop a selected job.
        restarted=ProductStore(raw)
        again=restarted.next_ready_job(TARGET+1000*FIVE_NS)
        assert (again['session_key'],again['target_ns'])==(chosen['session_key'],chosen['target_ns'])
        checks['restart_preserves_uncommitted_dirty_job']='PASS'
        evaluate(store,second)
        rate=next(v for v in json.loads(raw.execute('SELECT evaluation FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',
            (SESSION,second)).fetchone()['evaluation'])['decisions'] if v['family']=='rate_5m')
        assert rate['observed']==40 and rate['status']=='INSUFFICIENT_DATA' and rate['personal_history_windows']==8
        checks['second_burst_not_forced_into_an_alert_with_only_eight_past_windows']='PASS'
        # Isolate a continuously growing stream for the scheduler counterexample.
        raw.execute('DELETE FROM anomaly_detection.adp_jobs');raw.execute('DELETE FROM anomaly_detection.adp_source_windows')
        def add(target,session,complete=True):
            raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns) VALUES(%s,%s) ON CONFLICT DO NOTHING',(session,target))
            raw.execute('INSERT INTO anomaly_detection.adp_source_windows VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING',
                        (target,str(target),canonical({'generation':2}),complete))
        add(TARGET,SESSION)
        for i in range(4):
            add(TARGET+(i+1)*FIVE_NS,f'{i+1:064x}')
            assert store.next_job(TARGET+1000*FIVE_NS,recent=True)['target_ns']>TARGET
        checks['previous_newest_first_rule_can_continuously_defer_same_ready_target']='REPRODUCED'
        store.ready_pass=None
        seen=[]
        for i in range(6):
            add(TARGET+(i+10)*FIVE_NS,f'{i+100:064x}')
            choice=store.next_ready_job(TARGET+1000*FIVE_NS)
            if choice:
                seen.append(choice['target_ns'])
                raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=FALSE,last_evaluated_ns=%s,processed_version=version WHERE session_key=%s AND target_ns=%s',
                            (TARGET+1000*FIVE_NS,choice['session_key'],choice['target_ns']))
        assert TARGET in seen,seen
        assert seen[0]==TARGET
        checks['frozen_keyset_pass_cannot_be_overtaken_by_newer_windows']='PASS'
        old=TARGET-1000*FIVE_NS;add(old,'b'*64,False)
        assert store.next_job(TARGET+1000*FIVE_NS,recent=False)['target_ns']==old
        checks['historical_lane_keeps_all_ages_including_unready_windows']='PASS'
        report={'build_id':BUILD_ID,'environment':'ISOLATED_POSTGRESQL_WASM','owner_connections':0,'checks':checks,
                'native_windows_postgresql':'NOT_RUN','native_queue_latency':'NOT_MEASURED',
                'detector_gates_lowered':False,'native_precision_recall':'NOT_EVALUATED','status':'PASS_REVISION08'}
        (ROOT/'validation/PRODUCT_revision08.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report))
    finally:engine.close()


if __name__=='__main__':main()
