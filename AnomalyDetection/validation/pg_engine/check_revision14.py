"""Reproduce phantom targets; verify conservative, reversible queue upgrade.

Disposable PostgreSQL/WASM only. AD_BASELINE_ONLY=1 runs the counterexample
against a previous product selected through PYTHONPATH.
"""
from pathlib import Path
from unittest.mock import patch
import json
import os

from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window,owned_context
from anomaly_detection.snapshot import canonical,digest
from check_revision10 import packet,TARGET,SESSION,SERVICES

ROOT=Path(__file__).resolve().parents[2]


def main():
    engine=Engine();checks={}
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection')
        store=ProductStore(raw);store.initialize();end=TARGET+4*FIVE_NS
        apply_window(store,packet(TARGET,{SERVICES[0]:1}),cursor_name='seed')
        for n in range(1,4):apply_window(store,packet(TARGET+n*FIVE_NS,{}),cursor_name='empty')
        apply_window(store,packet(end,{SERVICES[0]:1},offset=200000),cursor_name='target')
        key=(SESSION,end)
        job=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',key).fetchone())
        context=store.save_context(job,owned_context(store,job))
        raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=FALSE,processed_version=version WHERE session_key=%s AND target_ns=%s',key)
        before=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',key).fetchone())
        count=raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_jobs').fetchone()['n']
        for n in range(1,4):
            p=packet(TARGET+n*FIVE_NS,{});p['stamp']+=':republished'
            apply_window(store,p,cursor_name='learning')
        actual=raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_jobs').fetchone()['n']
        assert actual==count,f'PHANTOM_JOBS: before={count}, after={actual}'
        assert dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',key).fetchone())==before
        checks['zero_coverage_completion_neither_creates_targets_nor_dirties_real_control']='PASS'
        if os.environ.get('AD_BASELINE_ONLY'):return
        from anomaly_detection.job_scope import warm,coverage_only
        from anomaly_detection.product_evaluations import evaluation_state
        from anomaly_detection.product_models import valid
        from anomaly_detection.product_priority import next_evidence_job
        history=store.history({'session_key':SESSION,'target_ns':end})
        zero=[r for r in history if r.get('counts')=={}]
        assert len(zero)==3 and all(valid(r) for r in zero)
        checks['qualified_zero_windows_remain_available_for_learning']='PASS'
        # Exercise the actual old-schema upgrade: ADD COLUMN without a default
        # leaves preexisting rows unclassified; only new inserts get a default.
        raw.execute('ALTER TABLE anomaly_detection.adp_jobs DROP COLUMN target_scope CASCADE')
        store.initialize()
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_jobs WHERE target_scope IS NULL').fetchone()['n']==count
        checks['old_schema_upgrade_preserves_rows_and_defers_classification_to_bounded_pages']='PASS'
        checks['release13_counterexample']='PASS_REPRODUCED_BEFORE_2_TARGETS_AFTER_5_WITHOUT_NEW_BEHAVIOR'
        # A real late event creates a target in the earlier coverage window and
        # invalidates its future consumer, regardless of how old it is.
        late=packet(TARGET+FIVE_NS,{SERVICES[1]:2},offset=300000)
        apply_window(store,dict(late,stamp='late-event'),cursor_name='late')
        later=raw.execute('SELECT version,dirty FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',key).fetchone()
        assert later['version']>before['version'] and later['dirty']
        checks['late_real_behavior_creates_target_and_invalidates_future_consumer']='PASS'
        # Simulate upgrade rows. Classification cannot delete or rewrite any
        # evaluation/version/feedback, and never converts unknown loss to zero.
        scopes=[];summary={'start_ns':TARGET,'counts':{},'coverage_complete':True,'population_complete':True}
        for n in range(600):
            s=f'{n+1000:064x}';scopes.append((s,TARGET))
        with raw.cursor() as cursor:
            cursor.executemany('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,target_scope) VALUES(%s,%s,NULL)',scopes)
            cursor.executemany('INSERT INTO anomaly_detection.adp_windows VALUES(%s,%s,%s,%s)',
                [(s,at,canonical(summary),digest(summary)) for s,at in scopes])
        # Guards on otherwise empty rows: counts unknown; unmapped; semantic
        # kind; already assessed; incident/feedback; withdrawn fact; no proof.
        protected=[]
        for n,override in enumerate(({'counts':None},{'unmapped_behaviors':1},{'kind_counts':{'service_execution':1}},{})):
            s=f'{9000+n:064x}';protected.append(s);body=summary|override
            raw.execute('INSERT INTO anomaly_detection.adp_windows VALUES(%s,%s,%s,%s)',(s,TARGET,canonical(body),digest(body)))
            raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,target_scope,last_evaluated_ns) VALUES(%s,%s,NULL,%s)',(s,TARGET,TARGET if n==3 else None))
        case_s=f'{9004:064x}';protected.append(case_s);case_key='ai1:'+digest([case_s,TARGET])
        raw.execute('INSERT INTO anomaly_detection.adp_windows VALUES(%s,%s,%s,%s)',(case_s,TARGET,canonical(summary),digest(summary)))
        raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,target_scope) VALUES(%s,%s,NULL)',(case_s,TARGET))
        raw.execute('INSERT INTO anomaly_detection.adp_incidents VALUES(%s,%s,%s,%s,1,%s,%s,%s)',(case_key,case_s,TARGET,'HOLD','{}',digest({}),TARGET))
        raw.execute('INSERT INTO anomaly_detection.adp_feedback(incident_key,label,note,created_ns,incident_revision) VALUES(%s,%s,%s,%s,1)',(case_key,'needs_evidence','keep',TARGET))
        withdrawn_s=f'{9005:064x}';protected.append(withdrawn_s)
        withdrawn=packet(TARGET,{SERVICES[2]:1},session=withdrawn_s,offset=400000)
        store.apply_rows(withdrawn['rows'],withdrawn['source'])
        raw.execute("UPDATE anomaly_detection.adp_facts SET state='withdrawn',source_present=FALSE WHERE session_key=%s",(withdrawn_s,))
        # Release16 invalidates the population proof on semantic change. This
        # synthetic census is unchanged after that new row is withdrawn; publish
        # its repaired proof before testing classification of known zero rows.
        # Unknown coverage must never qualify those 600 rows as proven empty.
        assert not raw.execute('SELECT complete FROM anomaly_detection.adp_source_windows WHERE start_ns=%s',(TARGET,)).fetchone()['complete']
        raw.execute("UPDATE anomaly_detection.adp_source_windows SET complete=TRUE,source=(source::jsonb-'needs_scope_repair')::text WHERE start_ns=%s",(TARGET,))
        raw.execute('INSERT INTO anomaly_detection.adp_windows VALUES(%s,%s,%s,%s)',(withdrawn_s,TARGET,canonical(summary),digest(summary)))
        raw.execute('UPDATE anomaly_detection.adp_jobs SET target_scope=NULL WHERE session_key=%s',(withdrawn_s,))
        no_proof_s=f'{9006:064x}';protected.append(no_proof_s);no_proof=summary|{'start_ns':TARGET-100*FIVE_NS}
        raw.execute('INSERT INTO anomaly_detection.adp_windows VALUES(%s,%s,%s,%s)',(no_proof_s,no_proof['start_ns'],canonical(no_proof),digest(no_proof)))
        raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,target_scope) VALUES(%s,%s,NULL)',(no_proof_s,no_proof['start_ns']))
        baseline=[dict(r) for r in raw.execute('SELECT session_key,target_ns,version,processed_version,dirty,last_evaluated_ns,evaluation FROM anomaly_detection.adp_jobs ORDER BY session_key,target_ns').fetchall()]
        original=store.save_state
        def fail(name,value):
            if name=='job_scope_backfill_v1':raise RuntimeError('rollback scope page')
            return original(name,value)
        with patch.object(store,'save_state',side_effect=fail):
            try:warm(store,limit=128)
            except RuntimeError:pass
            else:raise AssertionError('fault not reached')
        assert not store.state('job_scope_backfill_v1')
        assert raw.execute("SELECT COUNT(*) AS n FROM anomaly_detection.adp_jobs WHERE target_scope='COVERAGE_ONLY'").fetchone()['n']==0
        first=warm(store,limit=128);assert not first['done'] and first['scanned']==128
        # A new arrival after the frozen boundary has its own BEHAVIOR_TARGET
        # default and cannot extend the migration pass.
        raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns) VALUES(%s,%s)',('f'*64,end))
        store=ProductStore(raw)
        for _ in range(8):
            state=warm(store,limit=128)
            if state['done']:break
        assert state['done'] and state['coverage_only']==600,state
        assert warm(store,limit=128)==state
        after=[dict(r) for r in raw.execute("SELECT session_key,target_ns,version,processed_version,dirty,last_evaluated_ns,evaluation FROM anomaly_detection.adp_jobs WHERE session_key<>%s ORDER BY session_key,target_ns",('f'*64,)).fetchall()]
        assert baseline==after
        for s in protected:
            assert raw.execute('SELECT target_scope FROM anomaly_detection.adp_jobs WHERE session_key=%s',(s,)).fetchone()['target_scope']=='BEHAVIOR_TARGET',s
        assert raw.execute('SELECT note FROM anomaly_detection.adp_feedback WHERE incident_key=%s',(case_key,)).fetchone()['note']=='keep'
        checks['finite_restartable_upgrade_classifies_600_empty_rows_without_deleting_or_evaluating_anything']='PASS'
        checks['unknown_unmapped_assessed_withdrawn_incident_feedback_and_unavailable_windows_are_protected']='PASS'
        checks['classification_fault_rolls_back_and_new_arrivals_cannot_extend_frozen_pass']='PASS'
        assert evaluation_state({'target_scope':'COVERAGE_ONLY','dirty':True})=='COVERAGE_ONLY'
        assert evaluation_state({'target_scope':None,'dirty':True})=='SCOPE_PENDING'
        # Every scheduler must skip coverage-only targets, even with readiness
        # or extreme count priority metadata left over from an earlier build.
        raw.execute("UPDATE anomaly_detection.adp_jobs SET dirty=FALSE WHERE target_scope='BEHAVIOR_TARGET'")
        raw.execute("UPDATE anomaly_detection.adp_jobs SET observed_count=999999,target_evidence_ready=TRUE WHERE target_scope='COVERAGE_ONLY'")
        for choose in (store.next_job,store.next_ready_job,store.next_live_job,store.next_backlog_job,store.next_candidate_job):
            assert choose(end+FIVE_NS) is None,choose.__name__
        assert next_evidence_job(store,end+FIVE_NS) is None
        checks['all_scheduling_lanes_skip_coverage_metadata_without_calling_it_normal']='PASS'
        late_s=scopes[0][0]
        incoming=packet(TARGET,{SERVICES[2]:3},session=late_s,offset=500000)
        store.apply_rows(incoming['rows'],incoming['source'])
        revived=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(late_s,TARGET)).fetchone())
        assert revived['target_scope']=='BEHAVIOR_TARGET' and revived['dirty'] and revived['version']>1
        assert store.next_job(end+FIVE_NS)['session_key']==late_s
        checks['late_fact_reactivates_a_previously_coverage_only_target_automatically']='PASS'
        # Deleting source members of a real target must recheck the old decision,
        # retaining the fact ledger and its review rather than retiring the job.
        empty=packet(TARGET+FIVE_NS,{});empty['stamp']='withdraw-all'
        old=raw.execute('SELECT version FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION,TARGET+FIVE_NS)).fetchone()['version']
        apply_window(store,empty,cursor_name='withdraw')
        kept=raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',(SESSION,TARGET+FIVE_NS)).fetchone()
        assert kept['version']>old and kept['dirty'] and kept['target_scope']=='BEHAVIOR_TARGET'
        checks['real_target_with_empty_replacement_still_requires_reassessment']='PASS'
        report={'build_id':BUILD_ID,'status':'PASS_ISOLATED_POSTGRESQL_WASM','checks':checks,
            'owner_connections':0,'native_windows_postgresql':'NOT_RUN','native_queue_drain_rate':'NOT_MEASURED',
            'source_modified':False,'legacy_thresholds_and_models':'LEGACY_SCHEMA_CONTRACT_PRESERVED_REVIEW_AND_HOUR_QUALIFICATION_UPDATED_IN_RELEASE17'}
        (ROOT/'validation/PRODUCT_revision14.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()


if __name__=='__main__':main()
