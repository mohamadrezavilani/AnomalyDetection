"""Independent retry queue for secondary models; never blocks primary proof."""
from .snapshot import canonical
DDL=[
 'ALTER TABLE anomaly_detection.adp_jobs ADD COLUMN IF NOT EXISTS primary_version BIGINT NOT NULL DEFAULT 1',
 'ALTER TABLE anomaly_detection.adp_jobs ADD COLUMN IF NOT EXISTS primary_processed_version BIGINT',
 'ALTER TABLE anomaly_detection.adp_peer_dependencies ADD COLUMN IF NOT EXISTS reference_notified_epoch BIGINT',
 'ALTER TABLE anomaly_detection.adp_case_signals ADD COLUMN IF NOT EXISTS primary_version BIGINT',
 '''CREATE TABLE IF NOT EXISTS anomaly_detection.adp_model_queue(session_key TEXT NOT NULL,target_ns BIGINT NOT NULL,
 expected_version BIGINT NOT NULL,due_ns BIGINT NOT NULL,families TEXT NOT NULL,attempts BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(session_key,target_ns))''',
 'CREATE INDEX IF NOT EXISTS adp_model_due ON anomaly_detection.adp_model_queue(due_ns,target_ns,session_key)',
 "CREATE INDEX IF NOT EXISTS adp_signal_audit_scope ON anomaly_detection.adp_case_signals(target_ns DESC,job_session) WHERE state='ACTIVE' AND review_eligible=TRUE AND source_kind='actor'",
 'CREATE INDEX IF NOT EXISTS adp_peer_reference_scan_v1 ON anomaly_detection.adp_peer_dependencies(service_path,target_ns,session_key) INCLUDE(begin_ns,epoch) WHERE reference_notified_epoch IS NULL',
]


def schedule(store,job,families,now):
    from .behavior_scope import behavioral,DISABLED
    if behavioral(store.state('input_contract')):families=[f for f in families if f not in DISABLED]
    if not families:
        store.raw.execute('DELETE FROM anomaly_detection.adp_model_queue WHERE session_key=%s AND target_ns=%s',(job['session_key'],job['target_ns']));return
    store.raw.execute('INSERT INTO anomaly_detection.adp_model_queue(session_key,target_ns,expected_version,due_ns,families) VALUES(%s,%s,%s,%s,%s) ON CONFLICT(session_key,target_ns) DO UPDATE SET expected_version=excluded.expected_version,due_ns=excluded.due_ns,families=excluded.families',
        (job['session_key'],job['target_ns'],job['version'],now,canonical(sorted(set(families)))))


def next_job(store,now):
    row=store.raw.execute('SELECT j.* FROM anomaly_detection.adp_model_queue r JOIN anomaly_detection.adp_jobs j USING(session_key,target_ns) WHERE r.due_ns<=%s AND r.target_ns>=%s AND r.expected_version=j.version AND j.dirty=FALSE AND j.processed_version=j.version ORDER BY r.due_ns,r.target_ns,r.session_key LIMIT 1',(now,getattr(store,'history_floor_ns',0))).fetchone()
    return dict(row) if row else None


def defer(store,job,now):
    store.raw.execute('UPDATE anomaly_detection.adp_model_queue SET due_ns=%s,attempts=attempts+1 WHERE session_key=%s AND target_ns=%s AND expected_version=%s',
        (now+30_000_000_000,job['session_key'],job['target_ns'],job['version']))


def reference_changed(store,items):
    """Invalidate once while primary inputs are pending, in bounded PK batches.

    Epochs still advance on EVERY actual reference change. A computation whose
    job was already pending is rejected by the existing dependency-epoch CAS.
    Completion replaces dependency rows, reopening their notification tokens.
    Everything remains in the caller's atomic publication transaction.
    """
    scopes={}
    for service,at in items:
        if not service:continue
        low,high=scopes.get(service,(at,at));scopes[service]=(min(low,at),max(high,at))
    if not scopes:return
    values=canonical([{'name':'reference:'+s,'low':lo,'high':hi} for s,(lo,hi) in sorted(scopes.items())])
    source='SELECT * FROM jsonb_to_recordset(%s::jsonb) AS x(name TEXT,low BIGINT,high BIGINT)'
    with store.transaction():
        epochs=store.raw.execute('INSERT INTO anomaly_detection.adp_peer_epochs SELECT name,1 FROM ('+source+') x ORDER BY name '
            'ON CONFLICT(service_path) DO UPDATE SET version=adp_peer_epochs.version+1 RETURNING service_path,version',(values,)).fetchall()
        for row in epochs:
            name=row['service_path'];low,high=scopes[name.removeprefix('reference:')]
            after=None
            while True:
                fence='AND (target_ns,session_key)>(%s,%s) ' if after else ''
                page=store.raw.execute('SELECT session_key,target_ns FROM anomaly_detection.adp_peer_dependencies '
                    'WHERE service_path=%s AND reference_notified_epoch IS NULL AND target_ns>%s AND begin_ns<=%s '
                    +fence+'ORDER BY target_ns,session_key LIMIT 128',(name,low,high,*(after or ()))).fetchall()
                if not page:break
                after=(page[-1]['target_ns'],page[-1]['session_key'])
                keys=canonical([dict(r) for r in page])
                # First lock exact PKs, then mutate by TID in this statement.
                # A large pending queue cannot become a whole-table UPDATE.
                store.raw.execute('WITH wanted AS MATERIALIZED (SELECT * FROM jsonb_to_recordset(%s::jsonb) '
                    'AS x(session_key TEXT,target_ns BIGINT)) UPDATE anomaly_detection.adp_jobs SET '
                    'primary_processed_version=COALESCE(primary_processed_version,primary_version),'
                    'primary_version=primary_version+1,version=version+1,dirty=TRUE,due_ns=0 '
                    'WHERE ctid=ANY(ARRAY(SELECT j.ctid FROM wanted w CROSS JOIN LATERAL '
                    '(SELECT ctid FROM anomaly_detection.adp_jobs j WHERE j.session_key=w.session_key AND j.target_ns=w.target_ns '
                    'AND (NOT j.dirty OR j.due_ns<>0 OR j.primary_processed_version IS NULL '
                    'OR j.primary_processed_version=j.primary_version) LIMIT 1 FOR UPDATE) j))',(keys,))
                store.raw.execute('WITH wanted AS MATERIALIZED (SELECT * FROM jsonb_to_recordset(%s::jsonb) '
                    'AS x(session_key TEXT,target_ns BIGINT)) UPDATE anomaly_detection.adp_peer_dependencies '
                    'SET reference_notified_epoch=%s WHERE ctid=ANY(ARRAY(SELECT d.ctid FROM wanted w CROSS JOIN LATERAL '
                    '(SELECT ctid FROM anomaly_detection.adp_peer_dependencies d WHERE d.session_key=w.session_key '
                    'AND d.target_ns=w.target_ns AND d.service_path=%s AND d.reference_notified_epoch IS NULL '
                    'LIMIT 1 FOR UPDATE) d))',(keys,row['version'],name))
