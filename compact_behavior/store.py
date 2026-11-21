"""Atomic compact publication. No legacy tables, raw logs or financial graph."""

from __future__ import annotations
from collections import Counter
import re
import time
from . import CONTRACT, EXTRACTOR, FEATURES, FIVE
from .extract import Limits, LimitExceeded, digest, behavior_id, merge, materialize

ALL = "@all"
PENDING_WAIT_NS = 6 * FIVE
EXPIRED_RETENTION_NS = 30 * 24 * 12 * FIVE
NOTICE_RETENTION_NS = 7 * 24 * 12 * FIVE


def stream_lock(stream):
    return int(digest(stream)[:15], 16)


class Store:
    def __init__(
        self, config, *, schema="p24_compact", limits=Limits(), application="ingest"
    ):
        if not re.fullmatch(r"p24_compact(?:_[a-z0-9_]{1,40})?", schema):
            raise ValueError("compact_schema_required")
        import psycopg
        from psycopg.rows import dict_row

        parameters = {
            k: v
            for k, v in config.items()
            if k not in ("autocommit", "row_factory", "options", "application_name")
        }
        parameters.update(
            autocommit=True,
            row_factory=dict_row,
            connect_timeout=10,
            application_name="P24.Compact." + application,
            options="-c statement_timeout=60000 -c jit=off -c work_mem=32768",
        )
        self.conn = psycopg.connect(**parameters)
        self.schema = schema
        self.limits = limits

    def close(self):
        self.conn.close()

    def init(self):
        s = self.schema
        with self.conn.transaction():
            self.conn.execute(
                "SELECT pg_advisory_xact_lock(%s)", (stream_lock("schema:" + s),)
            )
            for statement in [
                f"CREATE SCHEMA IF NOT EXISTS {s}",
                f"""CREATE TABLE IF NOT EXISTS {s}.streams(stream_id TEXT PRIMARY KEY,contract TEXT NOT NULL,
                    extractor TEXT NOT NULL,feature_version TEXT NOT NULL,start_ns BIGINT NOT NULL,next_ns BIGINT NOT NULL,
                    change_epoch BIGINT NOT NULL DEFAULT 0)""",
                f"ALTER TABLE {s}.streams ADD COLUMN IF NOT EXISTS change_epoch BIGINT NOT NULL DEFAULT 0",
                f"""CREATE TABLE IF NOT EXISTS {s}.behaviors(behavior_id TEXT PRIMARY KEY,stream_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,session_id TEXT,observed_at_ns BIGINT,api TEXT,reported_duration DOUBLE PRECISION,
                    result_code TEXT,result_kind TEXT NOT NULL,kind TEXT NOT NULL,quality JSONB NOT NULL,
                    features JSONB NOT NULL,content_hash TEXT NOT NULL,revision BIGINT NOT NULL DEFAULT 1)""",
                f"CREATE INDEX IF NOT EXISTS compact_session_time ON {s}.behaviors(stream_id,session_id,observed_at_ns,behavior_id)",
                f"CREATE INDEX IF NOT EXISTS compact_time ON {s}.behaviors(stream_id,observed_at_ns,behavior_id)",
                f"CREATE TABLE IF NOT EXISTS {s}.behavior_payloads(behavior_id TEXT PRIMARY KEY,state JSONB NOT NULL)",
                f"""CREATE TABLE IF NOT EXISTS {s}.pending_requests(behavior_id TEXT PRIMARY KEY,stream_id TEXT NOT NULL,
                    state JSONB NOT NULL,content_hash TEXT NOT NULL,first_seen_ns BIGINT NOT NULL DEFAULT 0,
                    deadline_ns BIGINT NOT NULL DEFAULT 0,updated_at_ns BIGINT NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'WAITING')""",
                *[
                    f"ALTER TABLE {s}.pending_requests ADD COLUMN IF NOT EXISTS {column}"
                    for column in (
                        "first_seen_ns BIGINT NOT NULL DEFAULT 0",
                        "deadline_ns BIGINT NOT NULL DEFAULT 0",
                        "updated_at_ns BIGINT NOT NULL DEFAULT 0",
                        "status TEXT NOT NULL DEFAULT 'WAITING'",
                    )
                ],
                f"CREATE INDEX IF NOT EXISTS compact_pending_due ON {s}.pending_requests(stream_id,status,deadline_ns)",
                f"CREATE INDEX IF NOT EXISTS compact_pending_retention ON {s}.pending_requests(stream_id,status,updated_at_ns)",
                f"""CREATE TABLE IF NOT EXISTS {s}.expired_fragments(behavior_id TEXT PRIMARY KEY,stream_id TEXT NOT NULL,expired_at_ns BIGINT NOT NULL)""",
                f"""CREATE TABLE IF NOT EXISTS {s}.dirty_windows(stream_id TEXT NOT NULL,session_id TEXT NOT NULL,
                    start_ns BIGINT NOT NULL,version BIGINT NOT NULL DEFAULT 1,processed_version BIGINT NOT NULL DEFAULT 0,
                    updated_at_ns BIGINT NOT NULL DEFAULT 0,PRIMARY KEY(stream_id,session_id,start_ns))""",
                f"ALTER TABLE {s}.dirty_windows ADD COLUMN IF NOT EXISTS updated_at_ns BIGINT NOT NULL DEFAULT 0",
                f"""CREATE INDEX IF NOT EXISTS compact_dirty_ready ON {s}.dirty_windows(stream_id,start_ns,session_id)
                    WHERE processed_version<version""",
                f"""CREATE INDEX IF NOT EXISTS compact_dirty_retention ON {s}.dirty_windows(stream_id,updated_at_ns) WHERE processed_version=version""",
                f"""CREATE INDEX IF NOT EXISTS compact_dirty_global ON {s}.dirty_windows(stream_id,session_id,start_ns) WHERE processed_version<version""",
                f"""CREATE TABLE IF NOT EXISTS {s}.windows(stream_id TEXT NOT NULL,start_ns BIGINT NOT NULL,end_ns BIGINT NOT NULL,
                    source_records BIGINT NOT NULL,extracted_requests BIGINT NOT NULL,content_hash TEXT NOT NULL,
                    published_at_ns BIGINT NOT NULL DEFAULT 0,first_published_ns BIGINT NOT NULL DEFAULT 0,revision BIGINT NOT NULL DEFAULT 1,PRIMARY KEY(stream_id,start_ns))""",
                f"ALTER TABLE {s}.windows ADD COLUMN IF NOT EXISTS published_at_ns BIGINT NOT NULL DEFAULT 0",
                f"ALTER TABLE {s}.windows ADD COLUMN IF NOT EXISTS first_published_ns BIGINT NOT NULL DEFAULT 0",
                f"CREATE INDEX IF NOT EXISTS compact_publication_time ON {s}.windows(stream_id,first_published_ns,start_ns)",
                f"ALTER TABLE {s}.windows ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1",
                f"""CREATE TABLE IF NOT EXISTS {s}.queue_counts(stream_id TEXT PRIMARY KEY,active_pending BIGINT NOT NULL DEFAULT 0,
                    expired_pending BIGINT NOT NULL DEFAULT 0,dirty_keys BIGINT NOT NULL DEFAULT 0,
                    CHECK(active_pending>=0 AND expired_pending>=0 AND dirty_keys>=0))""",
            ]:
                self.conn.execute(statement)
            # Once for existing prototype namespaces, never a full queue count in publish.
            self.conn.execute(
                f"""INSERT INTO {s}.queue_counts SELECT stream_id,
                (SELECT count(*) FROM {s}.pending_requests p WHERE p.stream_id=x.stream_id AND p.status='WAITING'),
                (SELECT count(*) FROM {s}.pending_requests p WHERE p.stream_id=x.stream_id AND p.status='EXPIRED'),
                (SELECT count(*) FROM {s}.dirty_windows d WHERE d.stream_id=x.stream_id AND processed_version<version)
                FROM {s}.streams x WHERE NOT EXISTS(SELECT 1 FROM {s}.queue_counts q WHERE q.stream_id=x.stream_id)
                ON CONFLICT DO NOTHING"""
            )

    def cursor(self, stream):
        row = self.conn.execute(
            f"SELECT next_ns FROM {self.schema}.streams WHERE stream_id=%s", (stream,)
        ).fetchone()
        return row["next_ns"] if row else None

    def publish(
        self,
        stream,
        start,
        end,
        states,
        source_records,
        *,
        fault=None,
        allow_history=False,
        history_job=None,
    ):
        from psycopg.types.json import Jsonb

        if end - start != FIVE or start % FIVE:
            raise ValueError("aligned_five_minute_window_required")
        if len(states) > self.limits.requests:
            raise LimitExceeded("window_request_limit")
        s = self.schema
        began = time.monotonic()
        times = {}
        phase = time.monotonic()
        now = time.time_ns()
        context = self.conn.transaction()
        context.__enter__()
        exiting = False
        try:
            self.conn.execute(
                "SELECT pg_advisory_xact_lock(%s)", (stream_lock(stream),)
            )
            row = self.conn.execute(
                f"SELECT * FROM {s}.streams WHERE stream_id=%s FOR UPDATE", (stream,)
            ).fetchone()
            if history_job is not None:
                from .history import validate_publication
                if not row or not allow_history:
                    raise ValueError("history_job_requires_existing_stream_and_history_mode")
                validate_publication(self, stream, history_job, start, end)
            if row:
                if (row["contract"], row["extractor"], row["feature_version"]) != (
                    CONTRACT,
                    EXTRACTOR,
                    FEATURES,
                ):
                    raise ValueError("compact_input_contract_changed")
                if start > row["next_ns"]:
                    raise ValueError("compact_checkpoint_gap")
            else:
                self.conn.execute(
                    f"""INSERT INTO {s}.streams(stream_id,contract,extractor,feature_version,start_ns,next_ns)
                    VALUES(%s,%s,%s,%s,%s,%s)""",
                    (stream, CONTRACT, EXTRACTOR, FEATURES, start, start),
                )
                self.conn.execute(
                    f"INSERT INTO {s}.queue_counts(stream_id) VALUES(%s)", (stream,)
                )
            existed = self.conn.execute(
                f"SELECT content_hash FROM {s}.windows WHERE stream_id=%s AND start_ns=%s",
                (stream, start),
            ).fetchone()
            if row and start < row["next_ns"] and not existed:
                if not allow_history:
                    raise ValueError("window_before_stream_start")
                if start < row["next_ns"] - 288 * FIVE and history_job is None:
                    raise ValueError("reference_backfill_exceeds_24_hours")
            self.conn.execute(
                "CREATE TEMP TABLE compact_keys(behavior_id TEXT PRIMARY KEY) ON COMMIT DROP"
            )
            keyed = {behavior_id(stream, k): v for k, v in states.items()}
            with self.conn.cursor().copy("COPY compact_keys FROM STDIN") as copy:
                for key in keyed:
                    copy.write_row((key,))
            self.conn.execute("ANALYZE compact_keys")
            old = {
                r["behavior_id"]: r
                for r in self.conn.execute(
                    f"""SELECT k.behavior_id,p.state,b.session_id,
                    b.observed_at_ns,b.content_hash,b.revision,NULL::text AS pending_status FROM compact_keys k
                    CROSS JOIN LATERAL(SELECT * FROM {s}.behavior_payloads p WHERE p.behavior_id=k.behavior_id LIMIT 1) p JOIN {s}.behaviors b ON b.behavior_id=k.behavior_id
                    UNION ALL SELECT k.behavior_id,p.state,NULL,NULL,p.content_hash,0::bigint,p.status FROM compact_keys k
                    CROSS JOIN LATERAL(SELECT * FROM {s}.pending_requests p WHERE p.behavior_id=k.behavior_id LIMIT 1) p"""
                ).fetchall()
            }
            tombstones = {
                r["behavior_id"]
                for r in self.conn.execute(
                    f"""SELECT e.behavior_id FROM {s}.expired_fragments e
                JOIN compact_keys k USING(behavior_id)"""
                )
            }
            times["read_existing_seconds"] = time.monotonic() - phase
            phase = time.monotonic()
            window_hash = digest(sorted((k, digest(v)) for k, v in keyed.items()))
            changed = []
            pending = []
            dirty = (
                {(stream, ALL, start)}
                if not existed or existed["content_hash"] != window_hash
                else set()
            )
            quality = Counter()
            inserted = updated = unchanged = 0
            active_delta = expired_delta = 0
            for key, incoming in keyed.items():
                previous = old.get(key)
                state = (
                    merge(previous["state"], incoming, self.limits)
                    if previous
                    else incoming
                )
                if key in tombstones:
                    state["issues"] = sorted(
                        set(state["issues"] + ["prior_fragments_expired"])
                    )
                body = materialize(stream, state)
                if body is None:
                    signature = digest(state)
                    if not previous:
                        pending.append(
                            (
                                key,
                                stream,
                                Jsonb(state),
                                signature,
                                end,
                                end + PENDING_WAIT_NS,
                                now,
                                "WAITING",
                            )
                        )
                        active_delta += 1
                    elif signature != previous["content_hash"]:
                        pending.append(
                            (
                                key,
                                stream,
                                Jsonb(state),
                                signature,
                                end,
                                end + PENDING_WAIT_NS,
                                now,
                                previous["pending_status"],
                            )
                        )
                    continue
                quality.update(body["quality"])
                signature = digest([body, state])
                if (
                    previous
                    and previous["revision"]
                    and signature == previous["content_hash"]
                ):
                    unchanged += 1
                    continue
                inserted += not previous or not previous["revision"]
                updated += bool(previous and previous["revision"])
                if previous and previous["pending_status"] == "WAITING":
                    active_delta -= 1
                if previous and previous["pending_status"] == "EXPIRED":
                    expired_delta -= 1
                for st in [state] + ([previous["state"]] if previous else []):
                    ats = {
                        x["at_ns"] for x in st["roots"] if x.get("at_ns") is not None
                    }
                    if not ats and st["first_ns"] is not None:
                        ats = {st["first_ns"]}
                    for at in ats:
                        dirty.add((stream, ALL, at // FIVE * FIVE))
                        for session in st["sessions"]:
                            dirty.add((stream, session, at // FIVE * FIVE))
                changed.append(
                    (
                        key,
                        stream,
                        body["request_id"],
                        body["session_id"],
                        body["observed_at_ns"],
                        body["api"],
                        body["reported_duration"],
                        body["result_code"],
                        body["result_kind"],
                        body["kind"],
                        Jsonb(body["quality"]),
                        Jsonb(body["features"]),
                        signature,
                        Jsonb(state),
                    )
                )
            times["merge_features_seconds"] = time.monotonic() - phase
            phase = time.monotonic()
            self.conn.execute(
                f"CREATE TEMP TABLE compact_stage (LIKE {s}.behaviors INCLUDING DEFAULTS) ON COMMIT DROP"
            )
            self.conn.execute("ALTER TABLE compact_stage ADD COLUMN state JSONB")
            cols = "behavior_id,stream_id,request_id,session_id,observed_at_ns,api,reported_duration,result_code,result_kind,kind,quality,features,content_hash"
            with self.conn.cursor().copy(
                "COPY compact_stage(" + cols + ",state) FROM STDIN"
            ) as copy:
                for value in changed:
                    copy.write_row(value)
            assignment = ",".join(
                f"{name}=excluded.{name}"
                for name in cols.split(",")
                if name != "behavior_id"
            )
            self.conn.execute(
                f"""INSERT INTO {s}.behaviors({cols}) SELECT {cols} FROM compact_stage ORDER BY behavior_id
                ON CONFLICT(behavior_id) DO UPDATE SET {assignment},revision={s}.behaviors.revision+1
                WHERE {s}.behaviors.content_hash IS DISTINCT FROM excluded.content_hash"""
            )
            self.conn.execute(
                f"""INSERT INTO {s}.behavior_payloads SELECT behavior_id,state FROM compact_stage ORDER BY behavior_id
                ON CONFLICT(behavior_id) DO UPDATE SET state=excluded.state
                WHERE {s}.behavior_payloads.state IS DISTINCT FROM excluded.state"""
            )
            self.conn.execute(
                f"DELETE FROM {s}.pending_requests p USING compact_stage x WHERE p.behavior_id=x.behavior_id"
            )
            self.conn.execute(
                f"CREATE TEMP TABLE compact_pending (LIKE {s}.pending_requests) ON COMMIT DROP"
            )
            with self.conn.cursor().copy("COPY compact_pending FROM STDIN") as copy:
                for value in pending:
                    copy.write_row(value)
            self.conn.execute(
                f"""INSERT INTO {s}.pending_requests SELECT * FROM compact_pending ORDER BY behavior_id
                ON CONFLICT(behavior_id) DO UPDATE SET state=excluded.state,content_hash=excluded.content_hash,updated_at_ns=excluded.updated_at_ns
                WHERE {s}.pending_requests.content_hash IS DISTINCT FROM excluded.content_hash"""
            )
            # Bounded lifecycle; deadline never extends with every repeated fragment.
            expired = self.conn.execute(
                f"""WITH due AS(SELECT behavior_id FROM {s}.pending_requests
                WHERE stream_id=%s AND status='WAITING' AND deadline_ns<=%s ORDER BY deadline_ns LIMIT 5000)
                UPDATE {s}.pending_requests p SET status='EXPIRED' FROM due WHERE p.behavior_id=due.behavior_id""",
                (stream, max(end, row["next_ns"] if row else end)),
            ).rowcount
            active_delta -= expired
            expired_delta += expired
            purged = self.conn.execute(
                f"""WITH gone AS(DELETE FROM {s}.pending_requests WHERE behavior_id IN
                (SELECT behavior_id FROM {s}.pending_requests WHERE stream_id=%s AND status='EXPIRED'
                 AND updated_at_ns<%s ORDER BY updated_at_ns LIMIT 1000) RETURNING behavior_id,stream_id)
                ,saved AS(INSERT INTO {s}.expired_fragments SELECT behavior_id,stream_id,%s FROM gone ON CONFLICT DO NOTHING RETURNING 1)
                SELECT count(*) AS n FROM gone""",
                (stream, now - EXPIRED_RETENTION_NS, now),
            ).fetchone()["n"]
            expired_delta -= purged
            self.conn.execute(
                "CREATE TEMP TABLE compact_dirty(stream_id TEXT,session_id TEXT,start_ns BIGINT) ON COMMIT DROP"
            )
            with self.conn.cursor().copy("COPY compact_dirty FROM STDIN") as copy:
                for value in sorted(dirty):
                    copy.write_row(value)
            newly_dirty = self.conn.execute(
                f"""SELECT count(*) AS n FROM compact_dirty x LEFT JOIN {s}.dirty_windows d
                USING(stream_id,session_id,start_ns) WHERE d.version IS NULL OR d.processed_version=d.version"""
            ).fetchone()["n"]
            self.conn.execute(
                f"""INSERT INTO {s}.dirty_windows(stream_id,session_id,start_ns,updated_at_ns)
                SELECT stream_id,session_id,start_ns,%s FROM compact_dirty
                ON CONFLICT(stream_id,session_id,start_ns) DO UPDATE SET version={s}.dirty_windows.version+1,updated_at_ns=excluded.updated_at_ns""",
                (now,),
            )
            counts = self.conn.execute(
                f"""UPDATE {s}.queue_counts SET active_pending=active_pending+%s,
                expired_pending=expired_pending+%s,dirty_keys=dirty_keys+%s WHERE stream_id=%s RETURNING *""",
                (active_delta, expired_delta, newly_dirty, stream),
            ).fetchone()
            pending_total = counts["active_pending"]
            dirty_total = counts["dirty_keys"]
            if pending_total > self.limits.pending_requests:
                raise LimitExceeded("pending_request_limit_no_checkpoint_advance")
            if dirty_total > self.limits.dirty_windows:
                raise LimitExceeded("dirty_window_limit_no_checkpoint_advance")
            window_change = self.conn.execute(
                f"""INSERT INTO {s}.windows(stream_id,start_ns,end_ns,source_records,extracted_requests,content_hash,published_at_ns,first_published_ns)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(stream_id,start_ns)
                DO UPDATE SET source_records=excluded.source_records,extracted_requests=excluded.extracted_requests,
                content_hash=excluded.content_hash,published_at_ns=excluded.published_at_ns,revision={s}.windows.revision+1
                WHERE {s}.windows.content_hash IS DISTINCT FROM excluded.content_hash""",
                (
                    stream,
                    start,
                    end,
                    source_records,
                    len(states),
                    window_hash,
                    now,
                    now,
                ),
            ).rowcount
            self.conn.execute(
                f"""UPDATE {s}.streams SET next_ns=GREATEST(next_ns,%s),start_ns=LEAST(start_ns,%s),
                change_epoch=change_epoch+%s WHERE stream_id=%s""",
                (end, start, int(bool(changed or window_change)), stream),
            )
            self.conn.execute(
                f"""DELETE FROM {s}.dirty_windows d USING(SELECT stream_id,session_id,start_ns FROM {s}.dirty_windows
                WHERE stream_id=%s AND processed_version=version AND updated_at_ns<%s ORDER BY updated_at_ns LIMIT 1000) old
                WHERE (d.stream_id,d.session_id,d.start_ns)=(old.stream_id,old.session_id,old.start_ns)""",
                (stream, now - NOTICE_RETENTION_NS),
            )
            times["write_seconds"] = time.monotonic() - phase
            if history_job is not None:
                from .history import advance_publication
                advance_publication(self, history_job, end, source_records, not bool(existed), now)
            if fault:
                fault("before_commit")
            phase = time.monotonic()
            exiting = True
            context.__exit__(None, None, None)
            times["commit_seconds"] = time.monotonic() - phase
        except BaseException as exc:
            if not exiting:
                context.__exit__(type(exc), exc, exc.__traceback__)
            raise
        if fault:
            fault("after_commit")
        return dict(
            status="COMPACT_WINDOW_COMMITTED",
            fresh_publication=not bool(existed),
            start_ns=start,
            end_ns=end,
            source_records=source_records,
            requests=len(states),
            inserted=int(inserted),
            updated=int(updated),
            unchanged=unchanged,
            pending_requests=pending_total,
            expired_pending=counts["expired_pending"],
            dirty_windows=dirty_total,
            changed_quality=dict(quality),
            database_seconds=time.monotonic() - began,
            **times,
        )

    def measure(self):
        s = self.schema
        rows = self.conn.execute(
            """SELECT c.relname,pg_total_relation_size(c.oid) AS total_bytes
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relkind='r' ORDER BY c.relname""",
            (s,),
        ).fetchall()
        counts = {
            name: self.conn.execute(f"SELECT count(*) AS n FROM {s}.{name}").fetchone()[
                "n"
            ]
            for name in [
                "behaviors",
                "behavior_payloads",
                "pending_requests",
                "dirty_windows",
                "windows",
            ]
        }
        return dict(
            tables=[dict(x) for x in rows],
            rows=counts,
            total_bytes=sum(x["total_bytes"] for x in rows),
            backend_pid=self.conn.info.backend_pid,
            backend_stats_limitations="Diagnostic full counts are not run in continuous publication.",
        )
