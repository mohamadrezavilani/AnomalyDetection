"""Small isolated SQL regression: overlapping lanes, atomic publication and bulk invalidation.

AD_BASELINE_ONLY=1 runs only the interleaving counterexample against an older
package on PYTHONPATH. No network/owner database connection is opened.
"""
import json
import os
from pathlib import Path
from unittest.mock import patch
from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window,owned_context
from anomaly_detection.snapshot import canonical,digest

ROOT=Path(__file__).resolve().parents[2];TARGET=1_800_000_000_000_000_000//FIVE_NS*FIVE_NS
SESSION='a'*64;SERVICE='Services.v1/WaterBills'

def row(n):
    return {'request_key':f'{n:064x}','anchor_key':'ba1:'+f'{n+100:064x}','session_key':SESSION,
        'anchor_ns':TARGET+n,'kind':'service_execution','state':'active','revision':1,'root_call':SERVICE,
        'root_code':'G00000','identity_state':'assigned','conflicted':0,'request_session_key':SESSION}

def packet(rows,*,stamp='new',more=False):
    return {'target_ns':TARGET,'stamp':stamp,'rows':rows,'available':True,'has_more':more,
        'after':[rows[-1]['anchor_ns'],rows[-1]['request_key']] if more else None,
        'source':{'namespace':'viewer:test','stream_key':'test','keys_fingerprint':'test','generation':2 if stamp=='new' else 1,
            'semantic_generation':2 if stamp=='new' else 1,'captured_at_ns':TARGET+10*FIVE_NS}}

def count(store):
    return json.loads(store.raw.execute('SELECT body FROM anomaly_detection.adp_windows WHERE session_key=%s AND start_ns=%s',(SESSION,TARGET)).fetchone()['body'])['counts'][SERVICE]

def main():
    engine=Engine();checks={}
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
        apply_window(store,packet([row(99)],stamp='old'),cursor_name='seed')
        old_proof=dict(raw.execute('SELECT * FROM anomaly_detection.adp_source_windows WHERE start_ns=%s',(TARGET,)).fetchone())
        apply_window(store,packet([row(1),row(2)],more=True),cursor_name='A')
        apply_window(store,packet([row(3),row(4)],more=True),cursor_name='A')
        before_complete=count(store)
        before_proof=dict(raw.execute('SELECT * FROM anomaly_detection.adp_source_windows WHERE start_ns=%s',(TARGET,)).fetchone())
        apply_window(store,packet([row(1),row(2)],more=True),cursor_name='B')
        result=apply_window(store,packet([row(5)]),cursor_name='A')
        actual=count(store)
        assert actual==5,f'INTERLEAVED_WINDOW_UNDERCOUNT: expected=5 actual={actual}'
        checks['overlapping_lanes_cannot_erase_other_page_sets']='PASS'
        if os.environ.get('AD_BASELINE_ONLY'):return
        assert before_complete==1 and before_proof==old_proof
        checks['previous_complete_snapshot_remains_visible_until_commit']='PASS'
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_window_members WHERE start_ns=%s',(TARGET,)).fetchone()['n']==5
        assert apply_window(store,packet([row(3),row(4),row(5)]),cursor_name='B')['status']=='ALREADY_COMPLETE'
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_window_staging').fetchone()['n']==0
        checks['duplicate_lane_completion_is_idempotent_and_cleans_staging']='PASS'
        changed=packet([row(6),row(7)],stamp='next',more=True);changed['source'].update(generation=3,semantic_generation=3)
        apply_window(store,changed,cursor_name='C')
        other=dict(changed);apply_window(store,other,cursor_name='D')
        restart={'target_ns':TARGET,'restart':True,'rows':[],'stamp':'newer','source':changed['source']}
        apply_window(store,restart,cursor_name='C')
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_window_staging WHERE lane=%s',('D',)).fetchone()['n']==2
        assert count(store)==5
        checks['snapshot_restart_only_discards_its_own_lane']='PASS'
        final=dict(changed,rows=[row(8)],has_more=False,after=None)
        proof=dict(raw.execute('SELECT * FROM anomaly_detection.adp_source_windows WHERE start_ns=%s',(TARGET,)).fetchone())
        cursor=store.state('D');version=raw.execute('SELECT version FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION,TARGET)).fetchone()['version']
        with patch.object(store,'apply_cohort',side_effect=RuntimeError('injected')):
            try:apply_window(store,final,cursor_name='D')
            except RuntimeError:pass
            else:raise AssertionError('fault was not reached')
        assert count(store)==5 and store.state('D')==cursor
        assert dict(raw.execute('SELECT * FROM anomaly_detection.adp_source_windows WHERE start_ns=%s',(TARGET,)).fetchone())==proof
        assert raw.execute('SELECT version FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION,TARGET)).fetchone()['version']==version
        assert apply_window(store,final,cursor_name='D')['status']=='COMPLETE' and count(store)==3
        checks['publication_failure_rolls_back_members_facts_summaries_peer_and_cursor']='PASS'
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_window_versions').fetchone()['n']>=2
        checks['replaced_complete_window_bodies_are_preserved']='PASS'
        calls=[];original=engine.query
        def trace(role,sql,parameters):
            if isinstance(sql,str) and any(name in sql for name in ('anomaly_detection.adp_jobs','anomaly_detection.adp_incidents','anomaly_detection.adp_evidence_ready')):calls.append(sql)
            return original(role,sql,parameters)
        with patch.object(engine,'query',side_effect=trace):
            with store.transaction():store.invalidate_many([(f'{n+500:064x}',TARGET) for n in range(2000)])
        assert len(calls)==4,len(calls)
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_jobs WHERE target_ns=%s',(TARGET,)).fetchone()['n']==2001
        checks['2000_session_invalidations_use_four_set_based_statements_including_evidence_queue']='PASS'
        # Simulate the v06 upgrade contract while keeping all original bodies.
        from anomaly_detection.window_migration import migrate
        store.save_state('atomic_scope_v3',{})
        store.save_state('fresh_cursor',{'target_ns':TARGET,'after':[TARGET+2,'2'*64],'stamp':'old-unsafe'})
        before=count(store);migrate(store)
        body=json.loads(raw.execute('SELECT body FROM anomaly_detection.adp_windows WHERE session_key=%s AND start_ns=%s',(SESSION,TARGET)).fetchone()['body'])
        assert body['counts'][SERVICE]==before and not body['coverage_complete']
        assert store.state('fresh_cursor')=={'target_ns':TARGET}
        assert store.state('pre_atomic_cursor:fresh_cursor')['stamp']=='old-unsafe'
        assert owned_context(store,{'session_key':SESSION,'target_ns':TARGET}) is None
        assert raw.execute("SELECT COUNT(*) AS n FROM anomaly_detection.adp_window_versions WHERE reason='pre_atomic_scope_preserved'").fetchone()['n']>0
        saved=raw.execute('SELECT content_digest FROM anomaly_detection.adp_windows WHERE session_key=%s AND start_ns=%s',(SESSION,TARGET)).fetchone()['content_digest']
        assert saved==digest(body)
        checks['upgrade_quarantines_unsafe_scope_preserves_rows_and_resumes_full_snapshot']='PASS'
        report={'build_id':BUILD_ID,'environment':'POSTGRESQL_WASM_ISOLATED','owner_connections':0,'checks':checks,
            'native_windows_postgresql':'NOT_RUN','native_throughput':'NOT_MEASURED','status':'PASS_ATOMIC_SCOPE_AND_BULK_INVALIDATION'}
        (ROOT/'validation/PRODUCT_atomic_scope.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()

if __name__=='__main__':main()
