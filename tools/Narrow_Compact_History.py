"""Narrow an existing Compact history job in place, beside the running workers.

Run from the release root with python -m tools.Narrow_Compact_History.
The database audit and replacement job commit together. No window, evidence,
analysis result, live cursor or scheduled task is edited by this command.
"""
import argparse
import json
import time
import uuid
from pathlib import Path

from psycopg.types.json import Jsonb

from compact_ad import MODEL
from compact_behavior import FEATURES, FIVE
from compact_behavior.extract import instant, iso
from compact_behavior.history import latest
from compact_behavior.store import Store, stream_lock
from compact_product.config import load
from compact_product.health import health
from compact_product.history_schema import validate_installed
from viewer_performance.Diagnose_Three_Modes import controller_lock


def narrow(db, stream, previous, floor, target, deadline, *, wait_seconds=180, on_wait=None):
    if any(n % FIVE for n in (previous, floor, target, deadline)) or not previous < floor < target < deadline:
        raise ValueError("ordered_five_minute_scope_boundaries_required")
    stop = time.monotonic() + wait_seconds
    next_notice = 0
    while True:
        with db.conn.transaction():
            conn, schema = db.conn, db.schema
            conn.execute("SET LOCAL lock_timeout='2s'")
            conn.execute("SET LOCAL statement_timeout='10s'")
            if conn.execute("SELECT pg_try_advisory_xact_lock(%s) AS locked", (stream_lock(stream),)).fetchone()["locked"]:
                job = latest(db, stream)
                if not job or job["target_ns"] != target:
                    raise ValueError("expected_history_target_mismatch")
                if job["from_ns"] == floor:
                    audit = audit_for(db, job["job_id"])
                    if not audit or audit["previous_job"]["from_ns"] != previous or audit["deadline_ns"] != deadline:
                        raise ValueError("existing_scope_does_not_match_requested_change")
                    return "ALREADY_APPLIED"
                if job["from_ns"] != previous or job["state"] != "ACTIVE" or job["next_ns"] >= floor:
                    raise ValueError("active_history_has_changed_or_passed_requested_start")
                if time.time_ns() >= deadline:
                    raise ValueError("presentation_deadline_has_passed")
                live_next = db.cursor(stream)
                anchor = conn.execute(f"SELECT end_ns FROM {schema}.windows WHERE stream_id=%s AND start_ns=%s",
                                      (stream, target)).fetchone()
                if not anchor or anchor["end_ns"] != target + FIVE or live_next is None or live_next < target + FIVE:
                    raise ValueError("published_live_anchor_required")
                conn.execute(f"""CREATE TABLE IF NOT EXISTS {schema}.history_scope_changes(
                    job_id TEXT PRIMARY KEY, stream_id TEXT NOT NULL, previous_job JSONB NOT NULL,
                    from_ns BIGINT NOT NULL, deadline_ns BIGINT NOT NULL, applied_ns BIGINT NOT NULL)""")
                new_id, now = uuid.uuid4().hex, time.time_ns()
                conn.execute(f"INSERT INTO {schema}.history_scope_changes VALUES(%s,%s,%s,%s,%s,%s)",
                             (new_id, stream, Jsonb(job), floor, deadline, now))
                # An older in-flight fetch still carries the previous job ID.
                # The installed Writer verifies that ID under this same lock.
                changed = conn.execute(f"""UPDATE {schema}.history_jobs
                    SET job_id=%s,from_ns=%s,next_ns=%s,live_next_at_prepare_ns=%s,
                        published_windows=0,source_records=0,created_at_ns=%s,updated_at_ns=%s
                    WHERE stream_id=%s AND job_id=%s AND state='ACTIVE' AND next_ns=%s""",
                    (new_id, floor, floor, live_next, now, now, stream, job["job_id"], job["next_ns"])).rowcount
                if changed != 1:
                    raise ValueError("history_changed_before_scope_commit")
                return "APPLIED"
        now_poll = time.monotonic()
        if now_poll >= stop:
            raise TimeoutError("stream_busy_scope_not_changed")
        if on_wait and now_poll >= next_notice:
            on_wait()
            next_notice = now_poll + 10
        time.sleep(min(0.5, stop - now_poll))


def audit_for(db, job_id):
    if not db.conn.execute("SELECT to_regclass(%s) AS tab", (db.schema+".history_scope_changes",)).fetchone()["tab"]:
        return None
    return db.conn.execute(f"SELECT * FROM {db.schema}.history_scope_changes WHERE job_id=%s", (job_id,)).fetchone()


def coverage(db, ad_schema, stream, first, end):
    """Count exact aligned publications and their current base AD revisions."""
    if end < first or first % FIVE or end % FIVE:
        raise ValueError("invalid_coverage_range")
    row = db.conn.execute(f"""SELECT count(*) AS published,
        count(*) FILTER (WHERE r.model_version=%s AND r.feature_version=%s
            AND r.source_published_ns=w.published_at_ns AND r.timing_confirmed_revision=r.revision
            AND NOT EXISTS (SELECT 1 FROM {db.schema}.dirty_windows d WHERE d.stream_id=w.stream_id
                AND d.start_ns=w.start_ns AND d.processed_version<d.version)
            AND NOT EXISTS (SELECT 1 FROM {ad_schema}.reanalysis a WHERE a.stream_id=w.stream_id
                AND a.start_ns=w.start_ns AND a.processed_version<a.version)) AS analyzed_current
        FROM {db.schema}.windows w LEFT JOIN {ad_schema}.window_results r USING(stream_id,start_ns)
        WHERE w.stream_id=%s AND w.start_ns>=%s AND w.start_ns<%s AND w.start_ns %% %s=0
        AND w.end_ns=w.start_ns+%s""", (MODEL, FEATURES, stream, first, end, FIVE, FIVE)).fetchone()
    expected = (end-first)//FIVE
    return dict(from_utc=iso(first), through_utc_exclusive=iso(end), expected=expected,
                **row, missing_source=expected-row["published"], published_awaiting_ad=row["published"]-row["analyzed_current"])


def report(db, cfg, stream):
    with db.conn.transaction():
        db.conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        db.conn.execute("SET LOCAL statement_timeout='15s'")
        job = latest(db, stream)
        audit = audit_for(db, job["job_id"]) if job else None
        if not audit:
            raise ValueError("no_committed_narrowed_scope_for_latest_job")
        floor, target, deadline = job["from_ns"], job["target_ns"], audit["deadline_ns"]
        now = time.time_ns()
        closed = (now-cfg.source_lag_seconds*10**9)//FIVE*FIVE
        if closed < target:
            raise ValueError("clock_before_history_target")
        history = coverage(db, cfg.ad_schema, stream, floor, target)
        live = coverage(db, cfg.ad_schema, stream, target, closed)
        h = health(db.conn, cfg, stream)
        core = {name: h["roles"].get(name, {}) for name in ("ingest","analysis","web","supervisor")}
        def healthy(role):
            age = role.get("heartbeat_age_seconds")
            return bool(role.get("running") and isinstance(age, (int,float)) and 0 <= age <= 15
                        and not role.get("failure") and role.get("state") not in ("STARTING","STOPPED","RETRYING"))
        roles_healthy = all(healthy(role) for role in core.values())
        live_ok = roles_healthy and h["source_backlog_windows"] == 0
        current = all(x["analyzed_current"] == x["expected"] for x in (history,live))
        ready = job["state"] == "COMPLETE" and current and live_ok and h["reference_pending_windows"] == 0
        remaining = (target-job["next_ns"])//FIVE
        prior = audit["previous_job"]
        return dict(status="CONTIGUOUS_HISTORY_AND_LIVE_AD_CURRENT" if ready else "COMPACT_SCOPE_IN_PROGRESS",
                    checked_at_utc=iso(now), deadline_utc=iso(deadline), job_state=job["state"],
                    remaining_history_windows=remaining, next_utc=iso(job["next_ns"]),
                    required_history_windows_per_hour=round(remaining*3.6e12/(deadline-now),2) if now < deadline else None,
                    retained_earlier_windows_published_by_previous_job=prior["published_windows"],
                    excluded_untraversed_range_utc=[iso(prior["next_ns"]), iso(floor)],
                    history=history, live=live, live_roles_healthy=roles_healthy,
                    history_worker_running=bool(h["roles"].get("history",{}).get("running")),
                    source_backlog_windows=h["source_backlog_windows"],
                    analysis_pending_windows=h["analysis_pending_windows"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True)
    sub = parser.add_subparsers(dest="action", required=True)
    apply = sub.add_parser("apply")
    for arg in ("previous-from", "from", "target", "deadline"):
        apply.add_argument("--"+arg, dest=arg.replace("-","_")+"_ns", required=True, type=instant)
    sub.add_parser("status")
    args = parser.parse_args()
    db = None
    stage = "CONNECTING"
    try:
        project = args.project.resolve()
        cfg, source, stream = load(project)
        db = Store(source["DATABASE"], schema=cfg.source_schema, application="history.scope")
        if args.action == "apply":
            stage = "APPLYING_SCOPE"
            print('{"status":"CHECKING_EXISTING_HISTORY_SCOPE"}', flush=True)
            with controller_lock(project):
                validate_installed(db, stream, history_required=True)
                change = narrow(db, stream, args.previous_from_ns, args.from_ns, args.target_ns, args.deadline_ns,
                                on_wait=lambda: print('{"status":"WAITING_FOR_CURRENT_PUBLICATION"}', flush=True))
            print(json.dumps(dict(status="COMPACT_HISTORY_SCOPE_"+change)), flush=True)
        stage = "READING_SCOPE_STATUS"
        print(json.dumps(report(db, cfg, stream)), flush=True)
        return 0
    except Exception as exc:
        print(json.dumps(dict(status="COMPACT_SCOPE_COMMAND_INCOMPLETE",stage=stage,
                              failure=type(exc).__name__, code=str(exc) if isinstance(exc,(ValueError,TimeoutError)) else None,
                              sqlstate=getattr(exc,"sqlstate",None))),flush=True)
        return 2
    finally:
        if db:
            db.close()


if __name__ == "__main__":
    raise SystemExit(main())
