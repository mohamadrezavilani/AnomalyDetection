"""Recheck an existing candidate through the owned audit and evaluation path."""
import argparse
import json
from pathlib import Path
import sys
import time


MAX_REQUESTS = 16
AUDIT_BATCH_SIZE = 4
MODEL_STATEMENT_MS = 12000


def target_context(store, session, target):
    from anomaly_detection.primary_pipeline import context
    from anomaly_detection.snapshot import require

    job = store.raw.execute(
        "SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s "
        "AND target_scope='BEHAVIOR_TARGET'", (session, target)
    ).fetchone()
    require(job is not None, 'INPUT_RECHECK_JOB_NOT_FOUND')
    ctx = context(store, job)
    require(ctx and ctx['target_complete'] and ctx['target_events_complete'], 'INPUT_RECHECK_WINDOW_INCOMPLETE')
    return dict(job), ctx


def recheck(store, source, session, target):
    from anomaly_detection.input_subjects import CONTRACTS
    from anomaly_detection.presentation_proof import collect
    from anomaly_detection.primary_pipeline import evaluate
    from anomaly_detection.snapshot import api_path, require
    from anomaly_detection.sql_budget import statement_budget

    job, ctx = target_context(store, session, target)
    saved = json.loads(job['evaluation'] or '{}').get('decisions', [])
    counts = ctx['windows'][0]['counts']
    candidate_services = {
        row['service_path'] for row in saved
        if row['family']=='peer_service_rate_5m' and row['status']=='CANDIDATE'
        and row.get('baseline_unit')=='canonical_service_executions'
        and row['service_path'] in CONTRACTS and row['observed']==counts.get(row['service_path'])
    }
    require(candidate_services, 'INPUT_RECHECK_NO_COMPARABLE_RATE_CANDIDATE')
    events = {event['request_key']:event for event in ctx['events']
              if event['kind']=='service_execution' and api_path(event['root_call']) in candidate_services}
    require(0<len(events)<=MAX_REQUESTS and len(events)==sum(counts[s] for s in candidate_services),
            'INPUT_RECHECK_SCOPE_OUTSIDE_BUDGET')
    keys=sorted(events)
    audited=0
    for start in range(0,len(keys),AUDIT_BATCH_SIZE):
        batch=keys[start:start+AUDIT_BATCH_SIZE]
        snapshot=source.audit(batch)
        # Publication and an intervening late correction may otherwise refer
        # to different anchors. The regular worker handles those changes.
        for key in batch:
            old=events[key]
            current=snapshot.occurrences.get(key)
            require(current and all(current.get(k)==old.get(k) for k in
                ('anchor_key','revision','session_key','anchor_ns','root_call','kind','state')),
                'INPUT_RECHECK_SOURCE_CHANGED')
        store.apply_audit(snapshot)
        audited+=len(batch)

    # Evidence completion advances the primary version. Read that new version
    # and use the normal evaluator, current reference, and dependency CAS.
    job, ctx=target_context(store,session,target)
    with statement_budget(store.raw,MODEL_STATEMENT_MS):
        ctx=store.save_context(job,ctx)
        outcome=evaluate(store,dict(job,version=ctx['job_version']),ctx,time.time_ns())
        require(outcome['status']=='APPLIED','INPUT_RECHECK_VERSION_CHANGED')
    with store.raw.transaction():
        store.raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        proof=collect(store,session,target)
    return {
        'status':proof['status'],
        'audited_requests':audited,
        'source_window_complete':proof['source_window_complete'],
        'primary_input_current':proof['primary_input_current'],
        'services':[
            {'service_path':item['service_path'],'summary_executions':item['summary_executions'],
             'qualified_evidence_executions':item['qualified_evidence_executions'],
             'input_subject_finding':item['input_subject_finding']}
            for item in proof['services'] if item['service_path'] in candidate_services
        ],
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session',required=True)
    parser.add_argument('--target-tehran',required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(root))
    from run_anomaly import VerifiedApplicationFinder,verify_build
    sha=verify_build()
    sys.meta_path.insert(0,VerifiedApplicationFinder())
    from anomaly_detection import BUILD_ID
    from anomaly_detection.history_scope import WRITER_LOCK
    from anomaly_detection.native_pg import database
    from anomaly_detection.presentation_proof import target_time
    from anomaly_detection.process_control import OwnedProcessLock,safe_failure
    from anomaly_detection.product_source import ProductSource
    from anomaly_detection.product_store import ProductStore
    from anomaly_detection.snapshot import KEY,require
    try:
        require(KEY.fullmatch(args.session) is not None,'INPUT_RECHECK_INVALID_SESSION')
        target=target_time(args.target_tehran)
        with OwnedProcessLock(root,'input_recheck',sha):
            with database(root) as raw:
                acquired=raw.execute('SELECT pg_try_advisory_lock(%s) AS acquired',(WRITER_LOCK,)).fetchone()
                require(acquired and acquired['acquired'],'INPUT_RECHECK_WRITER_LEASE_BUSY')
                result=recheck(ProductStore(raw),ProductSource(root.parent),args.session,target)
    except Exception as exc:
        result={'status':'INPUT_RECHECK_DEFERRED','failure':safe_failure(exc)}
    print(json.dumps(result|{'build_id':BUILD_ID,'source_sha256':sha},ensure_ascii=True))


if __name__=='__main__':main()
