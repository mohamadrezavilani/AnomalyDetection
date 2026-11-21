"""Indexed freshness and readiness, not full evidence/queue scans."""

import time
from compact_behavior import FIVE, FEATURES
from compact_behavior.store import stream_lock
from compact_ad import MODEL
from compact_ad.methods import METHODS, OUT_OF_SCOPE


def health(db, config, stream):
    s = config.source_schema
    a = config.ad_schema
    now = time.time_ns()
    roles = {}
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
    source = db.execute(
        f"SELECT * FROM {s}.streams WHERE stream_id=%s", (stream,)
    ).fetchone()
    latest = db.execute(
        f"SELECT start_ns,published_at_ns FROM {s}.windows WHERE stream_id=%s ORDER BY start_ns DESC LIMIT 1",
        (stream,),
    ).fetchone()
    analyzed = db.execute(
        f"SELECT start_ns,analyzed_at_ns,readiness FROM {a}.window_results WHERE stream_id=%s ORDER BY start_ns DESC LIMIT 1",
        (stream,),
    ).fetchone()
    queue = (
        db.execute(
            f"SELECT * FROM {s}.queue_counts WHERE stream_id=%s", (stream,)
        ).fetchone()
        or {}
    )
    oldest = db.execute(
        f"""SELECT start_ns,updated_at_ns FROM {s}.dirty_windows WHERE stream_id=%s AND session_id='@all'
        AND processed_version<version ORDER BY start_ns LIMIT 1""",
        (stream,),
    ).fetchone()
    jobs = db.execute(
        f"SELECT count(*) AS n FROM {a}.reanalysis WHERE stream_id=%s AND processed_version<version",
        (stream,),
    ).fetchone()["n"]
    samples = db.execute(
        f"""SELECT publication_to_analysis_seconds FROM(
        SELECT GREATEST(0,(first_analyzed_ns-first_source_ns)/1e9::float) AS publication_to_analysis_seconds
        FROM {a}.window_results WHERE stream_id=%s ORDER BY first_analyzed_ns DESC LIMIT 288) x""",
        (stream,),
    ).fetchall()
    latencies = sorted(r["publication_to_analysis_seconds"] for r in samples)
    p95 = (
        latencies[max(0, __import__("math").ceil(len(latencies) * 0.95) - 1)]
        if latencies
        else None
    )
    closed = (now - config.source_lag_seconds * 10**9) // FIVE * FIVE
    return dict(
        roles=roles,
        service="compact_product",
        feature_version=FEATURES,
        model_version=MODEL,
        stream_id=stream,
        latest_received_end_ns=latest["start_ns"] + FIVE if latest else None,
        latest_analyzed_end_ns=analyzed["start_ns"] + FIVE if analyzed else None,
        source_backlog_windows=(
            max(0, (closed - source["next_ns"]) // FIVE) if source else None
        ),
        dirty_keys=queue.get("dirty_keys", 0),
        reanalysis_windows=jobs,
        active_pending=queue.get("active_pending", 0),
        expired_pending=queue.get("expired_pending", 0),
        oldest_dirty_start_ns=oldest["start_ns"] if oldest else None,
        oldest_unanalyzed_age_seconds=(
            (now - oldest["updated_at_ns"]) / 1e9 if oldest else None
        ),
        analysis_latency_p95_seconds=p95,
        analysis_latency_samples=len(latencies),
        latest_readiness=analyzed["readiness"] if analyzed else {},
        methods=METHODS,
        out_of_scope=OUT_OF_SCOPE,
        source_finality="NOT_ESTABLISHED",
        late_indexed_evidence_outside_overlap="EXPLICIT_RECHECK_REQUIRED",
        product_acceptance="SERVER_LONG_RUN_AND_LABELED_ACCURACY_NOT_YET_ESTABLISHED",
    )
