"""Bounded, indexed scheduling of completed evidence, independent of the model.

Metadata grants a queue turn only. The evaluator still checks current revision,
complete membership, counts, evidence and dependency CAS before any decision.
"""
from . import FIVE_NS
from .snapshot import canonical

DDL=[
    'ALTER TABLE anomaly_detection.adp_jobs ADD COLUMN IF NOT EXISTS target_evidence_ready BOOLEAN NOT NULL DEFAULT FALSE',
    'CREATE INDEX IF NOT EXISTS adp_job_evidence_recheck ON anomaly_detection.adp_jobs(last_evaluated_ns NULLS FIRST,target_ns,session_key) WHERE dirty=TRUE AND target_evidence_ready=TRUE',
    '''CREATE TABLE IF NOT EXISTS anomaly_detection.adp_evidence_ready(
       session_key TEXT NOT NULL,target_ns BIGINT NOT NULL,ready_ns BIGINT NOT NULL,
       PRIMARY KEY(session_key,target_ns))''',
    'CREATE INDEX IF NOT EXISTS adp_evidence_ready_order ON anomaly_detection.adp_evidence_ready(ready_ns,target_ns,session_key)',
    'CREATE INDEX IF NOT EXISTS adp_fact_audited_priority ON anomaly_detection.adp_facts(last_audit_ns DESC,request_key DESC) WHERE last_audit_ns>0',
]


def scopes_json(scopes):
    return canonical([{'session':s,'at':at} for s,at in sorted({(s,at//FIVE_NS*FIVE_NS) for s,at in scopes if s})])


def invalidate(store,scopes):
    store.raw.execute('WITH scopes AS (SELECT * FROM jsonb_to_recordset(%s::jsonb) AS x(session TEXT,at BIGINT)), '
        'removed AS (DELETE FROM anomaly_detection.adp_evidence_ready r USING scopes s '
        'WHERE r.session_key=s.session AND r.target_ns=s.at RETURNING r.session_key) '
        'UPDATE anomaly_detection.adp_jobs j SET target_evidence_ready=FALSE FROM scopes s '
        'WHERE j.session_key=s.session AND j.target_ns=s.at',
        (scopes_json(scopes),))


def refresh(store,scopes,now):
    """Refresh at most the scopes of one bounded audit/backfill batch."""
    scopes=list(set(scopes))
    if not scopes:return
    invalidate(store,scopes)
    store.raw.execute('WITH scopes AS (SELECT * FROM jsonb_to_recordset(%s::jsonb) AS x(session TEXT,at BIGINT)) '
        'INSERT INTO anomaly_detection.adp_evidence_ready '
        'SELECT j.session_key,j.target_ns,%s FROM scopes s JOIN anomaly_detection.adp_jobs j '
        'ON j.session_key=s.session AND j.target_ns=s.at '
        'WHERE EXISTS(SELECT 1 FROM anomaly_detection.adp_source_windows w WHERE w.start_ns=j.target_ns AND w.complete=TRUE) '
        "AND EXISTS(SELECT 1 FROM anomaly_detection.adp_facts f WHERE f.session_key=j.session_key AND f.at_ns>=j.target_ns "
        "AND f.at_ns<j.target_ns+%s AND f.state='active' AND f.eligible=TRUE) "
        'AND NOT EXISTS(SELECT 1 FROM anomaly_detection.adp_facts f WHERE f.session_key=j.session_key '
        "AND f.at_ns>=j.target_ns AND f.at_ns<j.target_ns+%s AND f.state='active' AND f.eligible=TRUE "
        "AND (f.source_present=FALSE OR f.details IS NULL OR f.details::jsonb->'quality'->>'evidence_available' IS DISTINCT FROM 'true' "
        "OR f.details::jsonb->'semantic'->>'revision' IS DISTINCT FROM f.revision::text "
        "OR f.details::jsonb->'semantic'->>'anchor_key' IS DISTINCT FROM f.anchor_key)) "
        'ON CONFLICT(session_key,target_ns) DO UPDATE SET ready_ns=excluded.ready_ns',
        (scopes_json(scopes),now,FIVE_NS,FIVE_NS))
    store.raw.execute('WITH scopes AS (SELECT * FROM jsonb_to_recordset(%s::jsonb) AS x(session TEXT,at BIGINT)) '
        'UPDATE anomaly_detection.adp_jobs j SET target_evidence_ready=TRUE FROM scopes s '
        'WHERE j.session_key=s.session AND j.target_ns=s.at AND EXISTS('
        'SELECT 1 FROM anomaly_detection.adp_evidence_ready r WHERE r.session_key=j.session_key AND r.target_ns=j.target_ns)',
        (scopes_json(scopes),))


def warm(store,now,limit=256):
    """One finite keyset pass over already audited facts on upgrade.

    A fact audited after the frozen boundary uses the normal refresh path.
    New arrivals cannot extend or repeatedly restart this pass.
    """
    state=store.state('evidence_priority_backfill_v2')
    if state.get('done'):return state
    state.setdefault('through_ns',now)
    params=[state['through_ns']];after=''
    if state.get('after'):
        after='AND (last_audit_ns,request_key)<(%s,%s) ';params.extend(state['after'])
    rows=store.raw.execute('SELECT session_key,at_ns,last_audit_ns,request_key FROM anomaly_detection.adp_facts '
        'WHERE last_audit_ns>0 AND last_audit_ns<=%s '+after+
        'ORDER BY last_audit_ns DESC,request_key DESC LIMIT %s',(*params,limit)).fetchall()
    with store.transaction():
        refresh(store,[(r['session_key'],r['at_ns']) for r in rows],now)
        state.update(done=len(rows)<limit,scanned=state.get('scanned',0)+len(rows))
        if rows:state['after']=[rows[-1]['last_audit_ns'],rows[-1]['request_key']]
        store.save_state('evidence_priority_backfill_v2',state)
    return state


def next_evidence_job(store,now):
    row=store.raw.execute('SELECT j.* FROM anomaly_detection.adp_jobs j '
        'WHERE j.target_scope=\'BEHAVIOR_TARGET\' AND j.dirty=TRUE AND j.target_evidence_ready=TRUE AND j.due_ns<=%s '
        'AND EXISTS(SELECT 1 FROM anomaly_detection.adp_source_windows w '
        'WHERE w.start_ns=j.target_ns AND w.complete=TRUE) '
        'ORDER BY j.last_evaluated_ns NULLS FIRST,j.target_ns,j.session_key LIMIT 1',(now,)).fetchone()
    return dict(row) if row else None
