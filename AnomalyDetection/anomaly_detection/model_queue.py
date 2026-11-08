"""Independent retry queue for secondary models; never blocks primary proof."""
from .snapshot import canonical
DDL=[
 'ALTER TABLE anomaly_detection.adp_jobs ADD COLUMN IF NOT EXISTS primary_version BIGINT NOT NULL DEFAULT 1',
 'ALTER TABLE anomaly_detection.adp_case_signals ADD COLUMN IF NOT EXISTS primary_version BIGINT',
 '''CREATE TABLE IF NOT EXISTS anomaly_detection.adp_model_queue(session_key TEXT NOT NULL,target_ns BIGINT NOT NULL,
 expected_version BIGINT NOT NULL,due_ns BIGINT NOT NULL,families TEXT NOT NULL,attempts BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(session_key,target_ns))''',
 'CREATE INDEX IF NOT EXISTS adp_model_due ON anomaly_detection.adp_model_queue(due_ns,target_ns,session_key)',
 "CREATE INDEX IF NOT EXISTS adp_signal_audit_scope ON anomaly_detection.adp_case_signals(target_ns DESC,job_session) WHERE state='ACTIVE' AND review_eligible=TRUE AND source_kind='actor'",
]


def schedule(store,job,families,now):
    if not families:
        store.raw.execute('DELETE FROM anomaly_detection.adp_model_queue WHERE session_key=%s AND target_ns=%s',(job['session_key'],job['target_ns']));return
    store.raw.execute('INSERT INTO anomaly_detection.adp_model_queue(session_key,target_ns,expected_version,due_ns,families) VALUES(%s,%s,%s,%s,%s) ON CONFLICT(session_key,target_ns) DO UPDATE SET expected_version=excluded.expected_version,due_ns=excluded.due_ns,families=excluded.families',
        (job['session_key'],job['target_ns'],job['version'],now,canonical(sorted(set(families)))))


def next_job(store,now):
    row=store.raw.execute('SELECT j.* FROM anomaly_detection.adp_model_queue r JOIN anomaly_detection.adp_jobs j USING(session_key,target_ns) WHERE r.due_ns<=%s AND r.expected_version=j.version AND j.dirty=FALSE AND j.processed_version=j.version ORDER BY r.due_ns,r.target_ns,r.session_key LIMIT 1',(now,)).fetchone()
    return dict(row) if row else None


def defer(store,job,now):
    store.raw.execute('UPDATE anomaly_detection.adp_model_queue SET due_ns=%s,attempts=attempts+1 WHERE session_key=%s AND target_ns=%s AND expected_version=%s',
        (now+30_000_000_000,job['session_key'],job['target_ns'],job['version']))


def reference_changed(store,items):
    """Only semantic reference changes invalidate primary-model versions."""
    scopes={}
    for service,at in items:
        if not service:continue
        low,high=scopes.get(service,(at,at));scopes[service]=(min(low,at),max(high,at))
    if not scopes:return
    values=canonical([{'name':'reference:'+s,'low':lo,'high':hi} for s,(lo,hi) in sorted(scopes.items())])
    source='SELECT * FROM jsonb_to_recordset(%s::jsonb) AS x(name TEXT,low BIGINT,high BIGINT)'
    store.raw.execute('INSERT INTO anomaly_detection.adp_peer_epochs SELECT name,1 FROM ('+source+') x ORDER BY name ON CONFLICT(service_path) DO UPDATE SET version=adp_peer_epochs.version+1',(values,))
    store.raw.execute('WITH x AS ('+source+'), affected AS (SELECT DISTINCT d.session_key,d.target_ns FROM x JOIN anomaly_detection.adp_peer_dependencies d ON d.service_path=x.name AND d.begin_ns<=x.high AND d.target_ns>x.low) UPDATE anomaly_detection.adp_jobs j SET primary_version=primary_version+1,version=version+1,dirty=TRUE,due_ns=0 FROM affected a WHERE j.session_key=a.session_key AND j.target_ns=a.target_ns',(values,))
