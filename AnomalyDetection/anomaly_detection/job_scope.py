"""Keep population coverage as learning history, separate from behavior targets.

The upgrade only labels provably empty, never-assessed targets. Facts of any
state, incidents, unknown counts and unavailable coverage protect a target.
Nothing is deleted or marked evaluated. Late evidence reactivates the target.
"""
import json

from . import FIVE_NS
from .snapshot import digest

DDL=[
    'ALTER TABLE anomaly_detection.adp_jobs ADD COLUMN IF NOT EXISTS target_scope TEXT',
    "ALTER TABLE anomaly_detection.adp_jobs ALTER COLUMN target_scope SET DEFAULT 'BEHAVIOR_TARGET'",
    "CREATE INDEX IF NOT EXISTS adp_first_scoped ON anomaly_detection.adp_jobs(target_ns,session_key) WHERE target_scope='BEHAVIOR_TARGET' AND dirty=TRUE AND last_evaluated_ns IS NULL",
    "CREATE INDEX IF NOT EXISTS adp_recheck_scoped ON anomaly_detection.adp_jobs(target_ns DESC,session_key DESC) WHERE target_scope='BEHAVIOR_TARGET' AND dirty=TRUE AND last_evaluated_ns IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS adp_job_behavior_work ON anomaly_detection.adp_jobs(due_ns,target_ns,session_key) WHERE target_scope='BEHAVIOR_TARGET' AND dirty=TRUE",
    "CREATE INDEX IF NOT EXISTS adp_job_behavior_time ON anomaly_detection.adp_jobs(target_ns,session_key) WHERE target_scope='BEHAVIOR_TARGET' AND dirty=TRUE",
    "CREATE INDEX IF NOT EXISTS adp_job_behavior_volume ON anomaly_detection.adp_jobs(observed_count DESC NULLS LAST,target_ns,session_key) WHERE target_scope='BEHAVIOR_TARGET' AND dirty=TRUE",
    "CREATE INDEX IF NOT EXISTS adp_job_behavior_evidence ON anomaly_detection.adp_jobs(last_evaluated_ns NULLS FIRST,target_ns,session_key) WHERE target_scope='BEHAVIOR_TARGET' AND dirty=TRUE AND target_evidence_ready=TRUE",
]


def coverage_only(summary):
    return bool(summary and summary.get('counts')=={} and
        summary.get('coverage_complete') is True and summary.get('population_complete',True) is True and
        not summary.get('unmapped_behaviors',0) and not summary.get('count_kinds') and
        not any((summary.get('kind_counts') or {}).values()) and
        summary.get('membership_digest',digest([]))==digest([]) and
        (summary.get('first_observed_ns') is None or
         summary['start_ns']>=summary['first_observed_ns']//FIVE_NS*FIVE_NS))


def projection(summary):
    if summary is None:return None
    result={k:summary.get(k) for k in ('coverage_complete','population_complete','counts','count_kinds',
        'kind_counts','unmapped_behaviors','membership_digest')}
    result.update(population_complete=summary.get('population_complete',True),
        count_kinds=summary.get('count_kinds') or {},kind_counts=summary.get('kind_counts') or {},
        unmapped_behaviors=summary.get('unmapped_behaviors',0))
    if coverage_only(summary):result['membership_digest']=summary.get('membership_digest',digest([]))
    return result


def warm(store,limit=4096):
    """Durable finite primary-key pass; new arrivals cannot extend the boundary."""
    state=store.state('job_scope_backfill_v1')
    if state.get('done'):return state
    with store.transaction():
        if 'through' not in state:
            last=store.raw.execute('SELECT session_key,target_ns FROM anomaly_detection.adp_jobs '
                'ORDER BY session_key DESC,target_ns DESC LIMIT 1').fetchone()
            state['through']=[last['session_key'],last['target_ns']] if last else None
        if state['through'] is None:
            state.update(done=True,scanned=0,coverage_only=0)
            store.save_state('job_scope_backfill_v1',state);return state
        after='';params=list(state['through'])
        if state.get('after'):
            after='AND (j.session_key,j.target_ns)>(%s,%s) ';params.extend(state['after'])
        rows=store.raw.execute('SELECT j.session_key,j.target_ns,j.target_scope,j.last_evaluated_ns,w.body,'
            'EXISTS(SELECT 1 FROM anomaly_detection.adp_source_windows sw WHERE sw.start_ns=j.target_ns AND sw.complete=TRUE) AS complete,'
            'EXISTS(SELECT 1 FROM anomaly_detection.adp_facts f WHERE f.session_key=j.session_key '
            'AND f.at_ns>=j.target_ns AND f.at_ns<j.target_ns+%s) AS has_fact,'
            'EXISTS(SELECT 1 FROM anomaly_detection.adp_incidents i WHERE i.session_key=j.session_key AND i.target_ns=j.target_ns) AS has_case '
            'FROM anomaly_detection.adp_jobs j LEFT JOIN anomaly_detection.adp_windows w '
            'ON w.session_key=j.session_key AND w.start_ns=j.target_ns '
            'WHERE (j.session_key,j.target_ns)<=(%s,%s) '+after+
            'ORDER BY j.session_key,j.target_ns LIMIT %s',(FIVE_NS,*params,limit)).fetchall()
        values=[];empty=0
        for row in rows:
            if row['target_scope'] is not None:continue
            summary=json.loads(row['body']) if row['body'] else None
            only=(row['last_evaluated_ns'] is None and row['complete'] and
                not row['has_fact'] and not row['has_case'] and coverage_only(summary))
            empty+=int(only)
            values.append({'session':row['session_key'],'at':row['target_ns'],
                'scope':'COVERAGE_ONLY' if only else 'BEHAVIOR_TARGET'})
        if values:
            from .snapshot import canonical
            store.raw.execute('UPDATE anomaly_detection.adp_jobs j SET target_scope=x.scope '
                'FROM jsonb_to_recordset(%s::jsonb) AS x(session TEXT,at BIGINT,scope TEXT) '
                'WHERE j.session_key=x.session AND j.target_ns=x.at AND j.target_scope IS NULL',(canonical(values),))
        state.update(done=len(rows)<limit,scanned=state.get('scanned',0)+len(rows),
            coverage_only=state.get('coverage_only',0)+empty)
        if rows:state['after']=[rows[-1]['session_key'],rows[-1]['target_ns']]
        store.save_state('job_scope_backfill_v1',state)
    return state


def promote_observed(store,limit=512):
    """Existing assessments/positive counters prove a real scheduling target.

    Use existing assessment/volume indexes instead of waiting for the global
    classification cursor to reach an actor's key. Only a scope label changes.
    A counter is scheduling metadata, never an anomaly decision or baseline.
    """
    state=store.state('job_scope_fast_promote_v1');before=dict(state)
    assessed=positive=0
    with store.transaction():
        if not state.get('assessed_done'):
            assessed=store.raw.execute('WITH candidates AS (SELECT session_key,target_ns '
                'FROM anomaly_detection.adp_jobs WHERE target_scope IS NULL AND last_evaluated_ns IS NOT NULL '
                'ORDER BY last_evaluated_ns DESC LIMIT %s) '
                "UPDATE anomaly_detection.adp_jobs j SET target_scope='BEHAVIOR_TARGET' FROM candidates c "
                'WHERE j.session_key=c.session_key AND j.target_ns=c.target_ns AND j.target_scope IS NULL',(limit,)).rowcount
            state['assessed_done']=assessed<limit
        if not state.get('positive_done'):
            positive=store.raw.execute('WITH candidates AS (SELECT session_key,target_ns '
                'FROM anomaly_detection.adp_jobs WHERE target_scope IS NULL AND dirty=TRUE '
                'AND last_evaluated_ns IS NULL AND observed_count>0 '
                'ORDER BY observed_count DESC NULLS LAST,target_ns,session_key LIMIT %s) '
                "UPDATE anomaly_detection.adp_jobs j SET target_scope='BEHAVIOR_TARGET' FROM candidates c "
                'WHERE j.session_key=c.session_key AND j.target_ns=c.target_ns AND j.target_scope IS NULL',(limit,)).rowcount
            state['positive_done']=positive<limit
        state['assessed_total']=state.get('assessed_total',0)+assessed
        state['positive_total']=state.get('positive_total',0)+positive
        if state!=before:store.save_state('job_scope_fast_promote_v1',state)
    return {'assessed':assessed,'positive':positive}
