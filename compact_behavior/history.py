"""Explicit, resumable historical ranges; separate from the live checkpoint."""

import time
import uuid
from . import CONTRACT, EXTRACTOR, FEATURES, FIVE
from .store import stream_lock


def initialize(store):
    s = store.schema
    with store.conn.transaction():
        store.conn.execute("SELECT pg_advisory_xact_lock(%s)", (stream_lock("schema:" + s),))
        store.conn.execute(f"""CREATE TABLE IF NOT EXISTS {s}.history_jobs(
            job_id TEXT PRIMARY KEY,stream_id TEXT NOT NULL,from_ns BIGINT NOT NULL,
            target_ns BIGINT NOT NULL,next_ns BIGINT NOT NULL,state TEXT NOT NULL,
            live_next_at_prepare_ns BIGINT NOT NULL,
            published_windows BIGINT NOT NULL DEFAULT 0,source_records BIGINT NOT NULL DEFAULT 0,
            created_at_ns BIGINT NOT NULL,updated_at_ns BIGINT NOT NULL,
            CHECK(from_ns<=next_ns AND next_ns<=target_ns),
            UNIQUE(stream_id,from_ns))""")
        store.conn.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS compact_history_one_active ON {s}.history_jobs(stream_id) WHERE state<>'COMPLETE'")


def latest(store, stream):
    if not store.conn.execute("SELECT to_regclass(%s) AS name", (store.schema+".history_jobs",)).fetchone()["name"]:
        return None
    return store.conn.execute(f"SELECT * FROM {store.schema}.history_jobs WHERE stream_id=%s ORDER BY created_at_ns DESC LIMIT 1", (stream,)).fetchone()


def prepare(store, stream, floor):
    if floor % FIVE:
        raise ValueError("history_start_must_align_to_five_minutes")
    initialize(store)
    s = store.schema
    with store.conn.transaction():
        store.conn.execute("SELECT pg_advisory_xact_lock(%s)", (stream_lock(stream),))
        source = store.conn.execute(f"SELECT * FROM {s}.streams WHERE stream_id=%s", (stream,)).fetchone()
        if not source or (source["contract"],source["extractor"],source["feature_version"]) != (CONTRACT,EXTRACTOR,FEATURES):
            raise ValueError("running_compatible_compact_stream_required")
        before = store.conn.execute(f"SELECT * FROM {s}.history_jobs WHERE stream_id=%s AND from_ns=%s", (stream,floor)).fetchone()
        if before:
            return before
        if store.conn.execute(f"SELECT 1 FROM {s}.history_jobs WHERE stream_id=%s AND state<>'COMPLETE'", (stream,)).fetchone():
            raise ValueError("another_history_range_is_active")
        target = store.conn.execute(f"SELECT min(start_ns) AS first FROM {s}.windows WHERE stream_id=%s", (stream,)).fetchone()["first"]
        if target is None or floor >= target:
            raise ValueError("history_start_must_precede_existing_compact_history")
        now = time.time_ns()
        return store.conn.execute(f"""INSERT INTO {s}.history_jobs(job_id,stream_id,from_ns,target_ns,next_ns,state,live_next_at_prepare_ns,created_at_ns,updated_at_ns)
            VALUES(%s,%s,%s,%s,%s,'ACTIVE',%s,%s,%s) RETURNING *""", (uuid.uuid4().hex,stream,floor,target,floor,source["next_ns"],now,now)).fetchone()


def validate_publication(store, stream, job_id, start, end):
    # Called inside publication, after the stream lock, not a stale pre-read.
    job = store.conn.execute(f"SELECT * FROM {store.schema}.history_jobs WHERE job_id=%s FOR UPDATE", (job_id,)).fetchone()
    if not job or job["stream_id"] != stream or job["state"] != "ACTIVE" or job["next_ns"] != start or end > job["target_ns"]:
        raise ValueError("history_range_or_cursor_not_authorized")


def advance_publication(store, job_id, end, records, fresh, now):
    store.conn.execute(f"""UPDATE {store.schema}.history_jobs SET next_ns=%s,
        state=CASE WHEN %s=target_ns THEN 'SOURCE_COMPLETE' ELSE 'ACTIVE' END,
        published_windows=published_windows+%s,source_records=source_records+%s,updated_at_ns=%s
        WHERE job_id=%s""", (end,end,int(fresh),records,now,job_id))


def finish(store, stream, job, ad_schema, model):
    """Source completion is distinct from acknowledged analysis completion."""
    s = store.schema
    with store.conn.transaction():
        store.conn.execute("SELECT pg_advisory_xact_lock(%s)", (stream_lock(stream),))
        ready = store.conn.execute(f"""SELECT 1 FROM {s}.history_jobs h WHERE job_id=%s AND stream_id=%s
            AND state='SOURCE_COMPLETE' AND next_ns=target_ns
            AND NOT EXISTS(SELECT 1 FROM {s}.dirty_windows d WHERE d.stream_id=h.stream_id
                AND d.start_ns>=h.from_ns AND d.start_ns<h.target_ns AND d.processed_version<d.version)
            AND NOT EXISTS(SELECT 1 FROM {ad_schema}.reanalysis r WHERE r.stream_id=h.stream_id
                AND r.start_ns>=h.from_ns AND r.start_ns<h.target_ns AND r.processed_version<r.version)
            AND (SELECT count(*) FROM {ad_schema}.window_results r WHERE r.stream_id=h.stream_id
                AND r.start_ns>=h.from_ns AND r.start_ns<h.target_ns AND r.feature_version=%s AND r.model_version=%s
                AND r.timing_confirmed_revision=r.revision)=(h.target_ns-h.from_ns)/%s""",
            (job["job_id"],stream,FEATURES,model,FIVE)).fetchone()
        if not ready:
            return False
        store.conn.execute(f"UPDATE {s}.history_jobs SET state='COMPLETE',updated_at_ns=%s WHERE job_id=%s", (time.time_ns(),job["job_id"]))
        return True
