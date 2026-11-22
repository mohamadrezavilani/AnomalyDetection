"""Incremental daily projections; bounded background work, no source replay.

Independent versioning avoids reanalysing every five-minute result on rollout.
Projection, daily profile and finding publication are each revision-fenced.
"""
import time
from compact_behavior import FIVE, FEATURES
from compact_behavior.extract import digest
from compact_behavior.store import stream_lock
from . import longitudinal as long


def initialize(conn, a):
    for sql in (
        f'''CREATE TABLE IF NOT EXISTS {a}.long_manifest(
            stream_id TEXT NOT NULL,start_ns BIGINT NOT NULL,published_ns BIGINT NOT NULL,
            version TEXT NOT NULL,PRIMARY KEY(stream_id,start_ns))''',
        f'''CREATE TABLE IF NOT EXISTS {a}.long_windows(
            stream_id TEXT NOT NULL,service TEXT NOT NULL,start_ns BIGINT NOT NULL,
            signature TEXT NOT NULL,payload BYTEA NOT NULL,PRIMARY KEY(stream_id,service,start_ns))''',
        f'''CREATE INDEX IF NOT EXISTS compact_long_window_time ON {a}.long_windows(stream_id,start_ns)''',
        f'''CREATE TABLE IF NOT EXISTS {a}.long_days(
            stream_id TEXT NOT NULL,service TEXT NOT NULL,day_ns BIGINT NOT NULL,
            version BIGINT NOT NULL DEFAULT 1,processed_version BIGINT NOT NULL DEFAULT 0,
            state TEXT NOT NULL DEFAULT 'PENDING',payload BYTEA,signature TEXT,
            PRIMARY KEY(stream_id,service,day_ns))''',
        f'''CREATE TABLE IF NOT EXISTS {a}.long_runs(
            stream_id TEXT NOT NULL,service TEXT NOT NULL,end_ns BIGINT NOT NULL,span INTEGER NOT NULL,
            state TEXT NOT NULL DEFAULT 'PENDING',retry_ns BIGINT NOT NULL DEFAULT 0,
            signature TEXT,details JSONB NOT NULL DEFAULT '{{}}',
            PRIMARY KEY(stream_id,service,end_ns,span))''',
        f'''CREATE INDEX IF NOT EXISTS compact_long_day_pending ON {a}.long_days(stream_id,day_ns)
            WHERE processed_version<version''',
        f'''CREATE INDEX IF NOT EXISTS compact_long_run_pending ON {a}.long_runs(stream_id,retry_ns,end_ns)
            WHERE state IN ('PENDING','WAITING')''',
    ):
        conn.execute(sql)


def prepare(summary, actors):
    prepared={}
    for service,profile in long.projection(summary, actors).items():
        try:
            payload=long.pack(profile)
        except long.CapacityExceeded:
            payload=long.pack({'@capacity_limit':True})
        prepared[service]=(digest([long.VERSION,profile]),payload)
    return prepared


def save(conn, a, stream, start, published, prepared):
    """Caller holds the source stream lock and has checked publication identity."""
    old = {r['service']: r['signature'] for r in conn.execute(
        f'SELECT service,signature FROM {a}.long_windows WHERE stream_id=%s AND start_ns=%s', (stream,start))}
    changed = sorted(k for k in old.keys() | prepared.keys()
                     if old.get(k) != (prepared[k][0] if k in prepared else None))
    for service in changed:
        if service in prepared:
            signature,payload = prepared[service]
            conn.execute(f'''INSERT INTO {a}.long_windows VALUES(%s,%s,%s,%s,%s)
                ON CONFLICT(stream_id,service,start_ns) DO UPDATE SET signature=excluded.signature,payload=excluded.payload''',
                (stream,service,start,signature,payload))
        else:
            conn.execute(f'DELETE FROM {a}.long_windows WHERE stream_id=%s AND service=%s AND start_ns=%s', (stream,service,start))
        day = long.day_start(start)
        conn.execute(f'''INSERT INTO {a}.long_days(stream_id,service,day_ns) VALUES(%s,%s,%s)
            ON CONFLICT(stream_id,service,day_ns) DO UPDATE SET version={a}.long_days.version+1,state='PENDING' ''',
            (stream,service,day))
        conn.execute(f'''UPDATE {a}.long_runs SET state='PENDING',retry_ns=0
            WHERE stream_id=%s AND service=%s AND end_ns>%s AND end_ns-span*%s<=%s''',
            (stream,service,day,long.DAY,day))
    conn.execute(f'''INSERT INTO {a}.long_manifest VALUES(%s,%s,%s,%s)
        ON CONFLICT(stream_id,start_ns) DO UPDATE SET published_ns=excluded.published_ns,version=excluded.version''',
        (stream,start,published,long.VERSION))


def coverage(conn, s, a, stream, start, end):
    row = conn.execute(f'''SELECT count(*) AS n,count(*) FILTER(WHERE m.published_ns=w.published_at_ns
        AND m.version=%s) AS ready FROM {s}.windows w LEFT JOIN {a}.long_manifest m USING(stream_id,start_ns)
        WHERE w.stream_id=%s AND w.start_ns>=%s AND w.start_ns<%s''',
        (long.VERSION,stream,start,end)).fetchone()
    return row['n'] == row['ready'] == (end-start)//FIVE


def build_day(db, stream):
    conn,s,a = db.conn,db.schema,db.ad_schema
    # Only closed, completely projected days. A sparse first day never blocks
    # later complete days; no source checkpoint is changed to manufacture zeroes.
    job = conn.execute(f'''WITH pending_days AS MATERIALIZED (
        SELECT DISTINCT day_ns FROM {a}.long_days WHERE stream_id=%s AND processed_version<version
        ), ready AS MATERIALIZED (SELECT day_ns FROM pending_days d WHERE
        (SELECT count(*) FROM {a}.long_manifest m JOIN {s}.windows w USING(stream_id,start_ns)
         WHERE m.stream_id=%s AND m.start_ns>=d.day_ns AND m.start_ns<d.day_ns+%s
         AND m.published_ns=w.published_at_ns AND m.version=%s)=288)
        SELECT p.* FROM {a}.long_days p JOIN ready USING(day_ns)
        WHERE p.stream_id=%s AND p.processed_version<p.version
        ORDER BY p.day_ns,p.service LIMIT 1''', (stream,stream,long.DAY,long.VERSION,stream)).fetchone()
    if not job:
        return None
    day,service = job['day_ns'],job['service']
    payload=None
    with conn.transaction():
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        try:
            with conn.cursor(name='compact_long_day') as cur:
                cur.itersize=4
                cur.execute(f'''SELECT payload FROM {a}.long_windows WHERE stream_id=%s
                    AND service=%s AND start_ns>=%s AND start_ns<%s ORDER BY start_ns''',
                    (stream,service,day,day+long.DAY))
                profile=long.merge(long.unpack(r['payload']) for r in cur)
            payload=long.pack(profile)
            signature=digest(profile)
            state='READY'
        except long.CapacityExceeded:
            state='LIMIT';signature=None
    with conn.transaction():
        conn.execute('SELECT pg_advisory_xact_lock(%s)',(stream_lock(stream),))
        if not coverage(conn,s,a,stream,day,day+long.DAY):
            return dict(status='LONGITUDINAL_RETRY')
        updated=conn.execute(f'''UPDATE {a}.long_days SET processed_version=version,state=%s,payload=%s,signature=%s
            WHERE stream_id=%s AND service=%s AND day_ns=%s AND version=%s''',
            (state,payload,signature,stream,service,day,job['version'])).rowcount
        if not updated:
            return dict(status='LONGITUDINAL_RETRY')
        for span in long.SPANS:
            conn.execute(f'''INSERT INTO {a}.long_runs(stream_id,service,end_ns,span) VALUES(%s,%s,%s,%s)
                ON CONFLICT(stream_id,service,end_ns,span) DO UPDATE SET state='PENDING',retry_ns=0''',
                (stream,service,day+long.DAY,span))
    return dict(status='LONGITUDINAL_DAY_PREPARED',day_ns=day,start_ns=day,state=state)


def period(db, stream, service, start, end):
    conn,s,a=db.conn,db.schema,db.ad_schema
    if not coverage(conn,s,a,stream,start,end):
        return None
    days=conn.execute(f'''SELECT day_ns,version,processed_version,state,signature FROM {a}.long_days
        WHERE stream_id=%s AND service=%s AND day_ns>=%s AND day_ns<%s ORDER BY day_ns''',
        (stream,service,start,end)).fetchall()
    if any(r['version']!=r['processed_version'] or r['state']!='READY' for r in days):
        return None
    # A service absent on a fully projected day contributes no activity. A day
    # with any service projection always has a long_days row, atomically.
    return days


def run_period(db, stream, *, fault=None):
    from psycopg.types.json import Jsonb
    conn,s,a=db.conn,db.schema,db.ad_schema
    now=time.time_ns()
    job=conn.execute(f'''SELECT * FROM {a}.long_runs WHERE stream_id=%s
        AND state IN ('PENDING','WAITING') AND retry_ns<=%s ORDER BY end_ns,span,service LIMIT 1''',
        (stream,now)).fetchone()
    if not job:
        return None
    service,end,span=job['service'],job['end_ns'],job['span']
    start=end-span*long.DAY
    with conn.transaction():
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        days=period(db,stream,service,start,end)
        signature=digest([[r['day_ns'],r['version'],r['signature']] for r in days]) if days is not None else None
        results=[];state='WAITING';details={'reason':'INCOMPLETE_PERIOD_OR_PROFILES'}
        if days is not None:
            try:
                with conn.cursor(name='compact_long_period') as cur:
                    cur.itersize=1
                    cur.execute(f'''SELECT payload FROM {a}.long_days WHERE stream_id=%s AND service=%s
                        AND day_ns>=%s AND day_ns<%s ORDER BY day_ns''',(stream,service,start,end))
                    actors=long.merge((long.unpack(r['payload']) for r in cur),active_days=True)
                readiness={}
                results=long.evaluate(actors,service=service,end=end,span=span,signature=signature,diagnostics=readiness)
                state='READY';details={'actors':len(actors),'findings':len(results),'complete_windows':span*288,
                                       'rule':long.VERSION,'period_start_ns':start,**readiness}
            except long.CapacityExceeded:
                state='LIMIT';details={'reason':'BOUNDED_PROFILE_CAPACITY'}
    with conn.transaction():
        conn.execute('SELECT pg_advisory_xact_lock(%s)',(stream_lock(stream),))
        current=period(db,stream,service,start,end) if days is not None else None
        if days is not None and (current is None or signature != digest([[r['day_ns'],r['version'],r['signature']] for r in current])):
            return dict(status='LONGITUDINAL_RETRY')
        previous={r['finding_id']:r for r in conn.execute(f'''SELECT * FROM {a}.findings
            WHERE stream_id=%s AND service=%s AND start_ns=%s AND method=%s
            AND (result->>'horizon_days')::int=%s''',(stream,service,end-FIVE,long.METHOD,span))}
        next_results={digest([long.VERSION,stream,service,end,span,r['session_id']]):r for r in results}
        for fid,old in previous.items():
            if fid not in next_results:
                next_results[fid]=dict(old['result'],status='INVALID_INPUT',reason='CUMULATIVE_RESULT_REVISED')
        for fid,result in next_results.items():
            old=previous.get(fid);rh=digest(result)
            if old and rh==old['result_hash']:
                continue
            revision=old['revision']+1 if old else 1
            conn.execute(f'''INSERT INTO {a}.findings VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(finding_id) DO UPDATE SET status=excluded.status,result=excluded.result,result_hash=excluded.result_hash,
                revision=excluded.revision,updated_at_ns=excluded.updated_at_ns''',
                (fid,stream,end-FIVE,long.METHOD,service,result['session_id'],result['status'],Jsonb(result),rh,
                 revision,old['first_seen_ns'] if old else now,now))
            conn.execute(f'INSERT INTO {a}.finding_history VALUES(%s,%s,%s,%s)',(fid,revision,Jsonb(result),now))
        conn.execute(f'''UPDATE {a}.long_runs SET state=%s,retry_ns=%s,signature=%s,details=%s
            WHERE stream_id=%s AND service=%s AND end_ns=%s AND span=%s''',
            (state,now+60*10**9,signature,Jsonb(details),stream,service,end,span))
        if fault:
            fault('before_commit')
    if fault:
        fault('after_commit')
    return dict(status='LONGITUDINAL_PERIOD_REVIEWED',state=state,start_ns=end-FIVE,horizon_days=span,**details)


def backfill(db, stream):
    """One existing compact window, no Elasticsearch and no base-result rewrite."""
    from .engine import summarize
    conn,s,a=db.conn,db.schema,db.ad_schema
    row=conn.execute(f'''SELECT w.start_ns,w.published_at_ns FROM {s}.windows w
        LEFT JOIN {a}.long_manifest m USING(stream_id,start_ns)
        WHERE w.stream_id=%s AND (m.start_ns IS NULL OR m.published_ns<>w.published_at_ns OR m.version<>%s)
        ORDER BY w.start_ns LIMIT 1''',(stream,long.VERSION)).fetchone()
    if not row:
        return None
    start=row['start_ns']
    with conn.transaction():
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        with conn.cursor(name='compact_long_projection') as cur:
            cur.itersize=200
            cur.execute(f'''SELECT behavior_id,session_id,result_code,features,kind,api,observed_at_ns,reported_duration
                FROM {s}.behaviors WHERE stream_id=%s AND observed_at_ns>=%s AND observed_at_ns<%s
                ORDER BY observed_at_ns,behavior_id''',(stream,start,start+FIVE))
            summary,_,actors=summarize(cur,cutoff_ns=start+FIVE,collect_longitudinal=True)
        prepared=prepare(summary,actors)
    with conn.transaction():
        conn.execute('SELECT pg_advisory_xact_lock(%s)',(stream_lock(stream),))
        current=conn.execute(f'SELECT published_at_ns FROM {s}.windows WHERE stream_id=%s AND start_ns=%s',(stream,start)).fetchone()
        if current['published_at_ns']!=row['published_at_ns']:
            return dict(status='LONGITUDINAL_RETRY')
        save(conn,a,stream,start,row['published_at_ns'],prepared)
    return dict(status='LONGITUDINAL_WINDOW_PREPARED',start_ns=start)


def step(db, stream, *, allow_backfill=True):
    # Background I/O cannot consume the normal 60-second statement budget.
    # A cancelled unit is retryable and has not ACKed any base work.
    from psycopg.errors import QueryCanceled, LockNotAvailable
    db.conn.execute('SET statement_timeout=5000')
    db.conn.execute('SET lock_timeout=1000')
    try:
        return build_day(db,stream) or run_period(db,stream) or (backfill(db,stream) if allow_backfill else None)
    except (QueryCanceled, LockNotAvailable):
        return dict(status='LONGITUDINAL_BUDGET_RETRY')
    finally:
        db.conn.execute('SET statement_timeout=60000')
        db.conn.execute('SET lock_timeout=0')


def eligible_sql(s, a):
    # SQL identifiers are already validated by the config/store. Version is a
    # code constant, not request input. Readiness is checked at display time.
    return f'''(f.method='{long.METHOD}' AND f.result->>'model_version'='{long.VERSION}'
        AND f.result->>'feature_version'='{FEATURES}'
        AND EXISTS(SELECT 1 FROM {a}.long_runs lr WHERE lr.stream_id=f.stream_id AND lr.service=f.service
            AND lr.end_ns=f.start_ns+{FIVE} AND lr.span=(f.result->>'horizon_days')::int
            AND lr.state='READY' AND lr.signature=f.result->>'reference_signature')
        AND NOT EXISTS(SELECT 1 FROM {s}.windows w LEFT JOIN {a}.long_manifest m USING(stream_id,start_ns)
            WHERE w.stream_id=f.stream_id AND w.start_ns>=(f.result->>'period_start_ns')::bigint
            AND w.start_ns<(f.result->>'period_end_ns')::bigint
            AND (m.start_ns IS NULL OR m.published_ns<>w.published_at_ns OR m.version<>'{long.VERSION}'))
        AND NOT EXISTS(SELECT 1 FROM {s}.dirty_windows d WHERE d.stream_id=f.stream_id AND d.session_id='@all'
            AND d.start_ns>=(f.result->>'period_start_ns')::bigint AND d.start_ns<(f.result->>'period_end_ns')::bigint
            AND d.processed_version<d.version))'''


def status(conn, s, a, stream):
    if not conn.execute('SELECT to_regclass(%s) AS name',(a+'.long_manifest',)).fetchone()['name']:
        return dict(version=long.VERSION,installed=False)
    counts=conn.execute(f'''SELECT count(*) AS source_windows,count(*) FILTER(WHERE m.published_ns=w.published_at_ns
        AND m.version=%s) AS projected_windows FROM {s}.windows w
        LEFT JOIN {a}.long_manifest m USING(stream_id,start_ns) WHERE w.stream_id=%s''',
        (long.VERSION,stream)).fetchone()
    days=conn.execute(f'''SELECT state,count(*) AS n FROM {a}.long_days WHERE stream_id=%s GROUP BY state''',(stream,)).fetchall()
    runs=conn.execute(f'''SELECT state,span,count(*) AS n FROM {a}.long_runs WHERE stream_id=%s GROUP BY state,span''',(stream,)).fetchall()
    return dict(version=long.VERSION,installed=True,**counts,day_profiles=days,period_reviews=runs)
