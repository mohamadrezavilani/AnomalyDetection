"""Indexed freshness and readiness, not full evidence/queue scans."""

import time
from compact_behavior import FIVE, FEATURES
from compact_behavior.extract import Limits
from compact_behavior.store import stream_lock
from compact_ad import MODEL
from compact_ad.methods import METHODS, OUT_OF_SCOPE


def health(db, config, stream):
    s = config.source_schema
    a = config.ad_schema
    now = time.time_ns()
    roles = {}
    reference_pending = None
    if db.execute("SELECT to_regclass(%s) AS name", (s + ".runtime_roles",)).fetchone()[
        "name"
    ]:
        rows = db.execute(
            f"""SELECT r.role,r.info,r.heartbeat_ns,l.classid,l.objid FROM {s}.runtime_roles r
            LEFT JOIN pg_stat_activity a ON a.pid=r.backend_pid AND a.backend_start=r.backend_start
            LEFT JOIN pg_locks l ON l.pid=a.pid AND l.locktype='advisory' AND l.granted AND l.objsubid=1"""
        ).fetchall()
        for row in rows:
            key = stream_lock(["compact-role", s, stream, row["role"]])
            locked = row["classid"] == key >> 32 and row["objid"] == key & 4294967295
            roles[row["role"]] = dict(
                running=locked,
                heartbeat_age_seconds=(now - row["heartbeat_ns"]) / 1e9,
                **row["info"],
            )
    if roles:
        ref = db.execute(
            f"SELECT next_ns,target_ns FROM {s}.reference_cursor WHERE stream_id=%s",
            (stream,),
        ).fetchone()
        if ref:
            reference_pending = max(0, (ref["target_ns"] - ref["next_ns"]) // FIVE)
    source = db.execute(
        f"SELECT * FROM {s}.streams WHERE stream_id=%s", (stream,)
    ).fetchone()
    latest = db.execute(
        f"SELECT start_ns,published_at_ns FROM {s}.windows WHERE stream_id=%s ORDER BY start_ns DESC LIMIT 1",
        (stream,),
    ).fetchone()
    analyzed = db.execute(
        f"""SELECT r.start_ns,r.analyzed_at_ns,r.readiness,r.revision,r.timing_confirmed_revision
        FROM {a}.window_results r JOIN {s}.windows w USING(stream_id,start_ns)
        WHERE r.stream_id=%s AND r.feature_version=%s AND r.model_version=%s
        AND r.source_published_ns=w.published_at_ns
        AND NOT EXISTS(SELECT 1 FROM {s}.dirty_windows d WHERE d.stream_id=r.stream_id
          AND d.start_ns=r.start_ns AND d.session_id='@all' AND d.processed_version<d.version)
        AND NOT EXISTS(SELECT 1 FROM {a}.reanalysis j WHERE j.stream_id=r.stream_id
          AND j.start_ns=r.start_ns AND j.processed_version<j.version)
        ORDER BY r.start_ns DESC LIMIT 1""",
        (stream, FEATURES, MODEL),
    ).fetchone()
    queue = (
        db.execute(
            f"SELECT * FROM {s}.queue_counts WHERE stream_id=%s", (stream,)
        ).fetchone()
        or {}
    )
    pending_sql = f"""SELECT start_ns,updated_at_ns FROM {s}.dirty_windows WHERE stream_id=%s
        AND session_id='@all' AND processed_version<version UNION ALL
        SELECT start_ns,updated_at_ns FROM {a}.reanalysis WHERE stream_id=%s AND processed_version<version"""
    oldest = db.execute(
        f"SELECT * FROM ({pending_sql}) pending ORDER BY start_ns LIMIT 1",
        (stream, stream),
    ).fetchone()
    pending_windows = db.execute(
        f"SELECT count(DISTINCT start_ns) AS n FROM ({pending_sql}) pending",
        (stream, stream),
    ).fetchone()["n"]
    jobs = db.execute(
        f"SELECT count(*) AS n FROM {a}.reanalysis WHERE stream_id=%s AND processed_version<version",
        (stream,),
    ).fetchone()["n"]
    samples = db.execute(
        f"""SELECT GREATEST(0,(first_analyzed_ns-first_source_ns)/1e9::float) AS first_analysis_seconds,
        GREATEST(0,(analyzed_at_ns-work_cause_ns)/1e9::float) AS revision_analysis_seconds
        FROM {a}.window_results WHERE stream_id=%s AND feature_version=%s AND model_version=%s AND first_analyzed_ns>0
        AND timing_confirmed_revision=revision ORDER BY analyzed_at_ns DESC LIMIT 288""",
        (stream, FEATURES, MODEL),
    ).fetchall()
    unconfirmed = db.execute(
        f"SELECT count(*) AS n FROM {a}.window_results WHERE stream_id=%s AND feature_version=%s AND model_version=%s AND timing_confirmed_revision<>revision",
        (stream, FEATURES, MODEL),
    ).fetchone()["n"]
    def p95(field):
        values = sorted(r[field] for r in samples)
        return values[max(0, __import__("math").ceil(len(values) * 0.95) - 1)] if values else None
    closed = (now - config.source_lag_seconds * 10**9) // FIVE * FIVE
    from .performance import recent
    return dict(
        performance=recent(db, s, stream),
        roles=roles,
        service="compact_product",
        feature_version=FEATURES,
        model_version=MODEL,
        stream_id=stream,
        latest_received_end_ns=latest["start_ns"] + FIVE if latest else None,
        latest_analyzed_end_ns=analyzed["start_ns"] + FIVE if analyzed else None,
        latest_analysis_timing_confirmed=bool(analyzed and analyzed["timing_confirmed_revision"] == analyzed["revision"]),
        source_backlog_windows=(
            max(0, (closed - source["next_ns"]) // FIVE) if source else None
        ),
        reference_pending_windows=reference_pending,
        dirty_keys=queue.get("dirty_keys", 0),
        reanalysis_windows=jobs,
        analysis_pending_windows=pending_windows,
        active_pending=queue.get("active_pending", 0),
        pending_high_water_warning=queue.get("active_pending", 0) > Limits().pending_requests,
        expired_pending=queue.get("expired_pending", 0),
        oldest_dirty_start_ns=oldest["start_ns"] if oldest else None,
        oldest_unanalyzed_age_seconds=(
            (now - oldest["updated_at_ns"]) / 1e9 if oldest else None
        ),
        analysis_timing_unconfirmed_windows=unconfirmed,
        analysis_latency_p95_seconds=p95("revision_analysis_seconds"),
        first_analysis_latency_p95_seconds=p95("first_analysis_seconds"),
        analysis_latency_scope="LATEST_REVISION_CAUSE_PRECOMMIT_TO_ANALYSIS_POSTCOMMIT; FIRST_ANALYSIS_REPORTED_SEPARATELY; INCLUDING_INSUFFICIENT_OR_INVALID; UNCONFIRMED_EXCLUDED",
        analysis_latency_samples=len(samples),
        latest_readiness=analyzed["readiness"] if analyzed else {},
        methods=METHODS,
        out_of_scope=OUT_OF_SCOPE,
        source_finality="NOT_ESTABLISHED",
        late_indexed_evidence_outside_overlap="EXPLICIT_RECHECK_REQUIRED",
        product_acceptance="SERVER_LONG_RUN_AND_LABELED_ACCURACY_NOT_YET_ESTABLISHED",
    )
