"""Refresh only verified input subject projections from retained PostgreSQL evidence.

No Elasticsearch read, window republication, cursor movement or service stop.
One window per transaction. Restart at the last printed window if interrupted.
"""
import argparse
from collections import Counter
import json
import time
from pathlib import Path

from compact_behavior import FIVE, inquiry
from compact_behavior.extract import digest, instant, iso, materialize
from compact_behavior.store import ALL, Store, stream_lock
from compact_product.config import load


def refresh(db, stream, start, *, apply=False):
    from psycopg.types.json import Jsonb

    s, conn = db.schema, db.conn
    counts, changes = Counter(), []
    with conn.transaction():
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        conn.execute("SET LOCAL statement_timeout='30s'")
        if not conn.execute(f'SELECT 1 FROM {s}.windows WHERE stream_id=%s AND start_ns=%s',
                            (stream, start)).fetchone():
            return dict(status='WINDOW_UNPUBLISHED', start=iso(start))
        with conn.cursor(name='compact_inquiry_legacy') as cur:
            cur.itersize = 64
            cur.execute(f'''SELECT b.behavior_id,b.content_hash,b.features,p.state
                FROM {s}.behaviors b LEFT JOIN {s}.behavior_payloads p USING(behavior_id)
                WHERE b.stream_id=%s AND b.observed_at_ns>=%s AND b.observed_at_ns<%s
                AND b.features->>'service_key'=ANY(%s)
                AND b.features->'input_feature_eligibility'->>'targets'='true'
                AND NOT (b.features ? %s)''',
                (stream, start, start + FIVE, list(inquiry.ROUTES), inquiry.POLICY))
            for row in cur:
                counts['legacy'] += 1
                if counts['legacy'] > db.limits.requests:
                    raise ValueError('inquiry_window_size_limit')
                state = row['state']
                body = materialize(stream, state) if state else None
                if not body or inquiry.POLICY not in body['features']:
                    raise ValueError('retained_input_requires_source_review')
                expected = body['features'].pop(inquiry.POLICY)
                # Refuse to sign or overwrite unrelated extraction differences.
                if body['features'] != row['features'] or digest([body, state]) != row['content_hash']:
                    raise ValueError('legacy_behavior_revision_requires_source_review')
                body['features'][inquiry.POLICY] = expected
                counts['verified_target' if expected else 'target_unavailable'] += 1
                changes.append((row['behavior_id'], row['content_hash'], digest([body, state]), Jsonb(expected)))
    if apply and changes:
        with conn.transaction():
            conn.execute("SET LOCAL lock_timeout='2s'")
            conn.execute("SET LOCAL statement_timeout='30s'")
            conn.execute('CREATE TEMP TABLE inquiry_patch(id text,old_hash text,new_hash text,subjects jsonb) ON COMMIT DROP')
            with conn.cursor().copy('COPY inquiry_patch FROM STDIN') as copy:
                for change in changes:
                    copy.write_row(change)
            conn.execute('ANALYZE inquiry_patch')
            deadline = time.monotonic() + 180
            lock = stream_lock(stream)
            while not conn.execute('SELECT pg_try_advisory_xact_lock(%s) AS got',(lock,)).fetchone()['got']:
                if time.monotonic() >= deadline:
                    raise TimeoutError('inquiry_stream_busy')
                print(json.dumps(dict(status='WAITING_FOR_CURRENT_PUBLICATION', start=iso(start))), flush=True)
                time.sleep(5)
            # The producer and AD commit use this same lock. A changed row forces
            # the entire window to retry, including dirty accounting.
            updated = conn.execute(f'''UPDATE {s}.behaviors b SET
                features=jsonb_set(b.features,%s,p.subjects),content_hash=p.new_hash,revision=b.revision+1
                FROM inquiry_patch p WHERE b.behavior_id=p.id AND b.content_hash=p.old_hash AND b.stream_id=%s''',
                ([inquiry.POLICY], stream)).rowcount
            if updated != len(changes):
                raise RuntimeError('inquiry_window_revision_changed')
            # AD processes the entire window under @all. No session, timestamp,
            # membership, publication or checkpoint changed.
            row = conn.execute(f'''SELECT processed_version=version AS clean FROM {s}.dirty_windows
                WHERE stream_id=%s AND session_id=%s AND start_ns=%s''', (stream, ALL, start)).fetchone()
            conn.execute(f'''INSERT INTO {s}.dirty_windows(stream_id,session_id,start_ns,updated_at_ns)
                VALUES(%s,%s,%s,%s) ON CONFLICT(stream_id,session_id,start_ns) DO UPDATE
                SET version={s}.dirty_windows.version+1,updated_at_ns=excluded.updated_at_ns''',
                (stream, ALL, start, time.time_ns()))
            conn.execute(f'UPDATE {s}.queue_counts SET dirty_keys=dirty_keys+%s WHERE stream_id=%s',
                         (int(not row or row['clean']), stream))
            conn.execute(f'UPDATE {s}.streams SET change_epoch=change_epoch+1 WHERE stream_id=%s', (stream,))
            counts['updated'] = updated
    return dict(status='INQUIRY_WINDOW_APPLIED' if apply else 'INQUIRY_WINDOW_PREVIEW', start=iso(start), **counts)


def latest_coverage(db, cfg, stream):
    """One published window; use the AD summary and revision fences, never the evidence table."""
    s, a = db.schema, cfg.ad_schema
    with db.conn.transaction():
        db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        db.conn.execute("SET LOCAL statement_timeout='5s'")
        row = db.conn.execute(f"""SELECT w.start_ns,r.summary,r.source_published_ns=w.published_at_ns
              AND r.timing_confirmed_revision=r.revision
              AND NOT EXISTS(SELECT 1 FROM {s}.dirty_windows d WHERE d.stream_id=w.stream_id
                 AND d.start_ns=w.start_ns AND d.session_id='@all' AND d.processed_version<d.version)
              AND NOT EXISTS(SELECT 1 FROM {a}.reanalysis j WHERE j.stream_id=w.stream_id
                 AND j.start_ns=w.start_ns AND j.processed_version<j.version) AS current
            FROM {s}.windows w LEFT JOIN {a}.window_results r USING(stream_id,start_ns)
            WHERE w.stream_id=%s ORDER BY w.start_ns DESC LIMIT 1""",(stream,)).fetchone()
    if not row or not row['current']:
        return dict(status='LATEST_INQUIRY_WINDOW_AWAITING_AD',start=iso(row['start_ns']) if row else None)
    services = {service: dict(requests=h['count'],usable_input=h['input_valid'],
                    axes={axis: values['covered'] for axis,values in h[inquiry.POLICY].items()})
                for service,h in row['summary']['services'].items() if inquiry.POLICY in h}
    return dict(status='LATEST_INQUIRY_COVERAGE',start=iso(row['start_ns']),services=services,
                count_scope='COMPLETE_SESSION_SERVICE_FIELD_COVERAGE_IN_THIS_WINDOW')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, required=True)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument('--from', dest='begin')
    scope.add_argument('--latest', action='store_true', help='Print field coverage for the latest published window')
    parser.add_argument('--until', help='Exclusive; default is one five-minute window')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if args.latest and (args.apply or args.until):
        parser.error('--latest is a single read-only observation')
    if not args.latest:
        begin = instant(args.begin)
        end = instant(args.until) if args.until else begin + FIVE
        if begin % FIVE or end % FIVE or end <= begin:
            parser.error('aligned, nonempty five-minute range required')
    cfg, source, stream = load(args.project.resolve())
    db = Store(source['DATABASE'], schema=cfg.source_schema, application='compact-inquiry-repair')
    try:
        if args.latest:
            print(json.dumps(latest_coverage(db, cfg, stream)), flush=True)
            return 0
        if args.apply:
            from compact_product.version import verify
            package = verify()['source_sha256']
            roles = db.conn.execute(f"SELECT role,info->'package'->>'source_sha256' AS sha FROM {db.schema}.runtime_roles").fetchall()
            installed = {r['role']:r['sha'] for r in roles}
            job = db.conn.execute(f"SELECT state FROM {db.schema}.history_jobs WHERE stream_id=%s ORDER BY created_at_ns DESC LIMIT 1",(stream,)).fetchone()
            active_history = job and job['state'] in ('ACTIVE','SOURCE_COMPLETE')
            if any(installed.get(r) != package for r in ('ingest','analysis')) or (active_history and installed.get('history') != package):
                raise ValueError('install_matching_writers_before_target_repair')
        for start in range(begin, end, FIVE):
            if args.apply and end - begin > FIVE:
                # Share the machine with the existing live and history workers.
                # Never enqueue another window while base/reanalysis work is outstanding.
                while True:
                    busy = db.conn.execute(f"""SELECT
                        EXISTS(SELECT 1 FROM {db.schema}.dirty_windows WHERE stream_id=%s
                            AND session_id='@all' AND processed_version<version) OR
                        EXISTS(SELECT 1 FROM {cfg.ad_schema}.reanalysis WHERE stream_id=%s
                            AND processed_version<version) AS busy""", (stream, stream)).fetchone()['busy']
                    if not busy:
                        break
                    print(json.dumps(dict(status='WAITING_FOR_AD', resume_from=iso(start))), flush=True)
                    time.sleep(30)
            print(json.dumps(dict(status='CHECKING_INQUIRY_WINDOW', start=iso(start))), flush=True)
            try:
                result = refresh(db, stream, start, apply=args.apply)
            except Exception as exc:
                print(json.dumps(dict(status='INQUIRY_WINDOW_INCOMPLETE', resume_from=iso(start),
                                      error=type(exc).__name__, sqlstate=getattr(exc,'sqlstate',None),
                                      reason=str(exc) if isinstance(exc,(ValueError,RuntimeError)) else None)), flush=True)
                return 2
            print(json.dumps(result), flush=True)
    finally:
        db.close()
    return 0


if __name__=='__main__':
    raise SystemExit(main())
