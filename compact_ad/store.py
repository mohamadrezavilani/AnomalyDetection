"""Snapshot computation, then version-fenced atomic result publication and ACK."""

from collections import Counter
import re
import time
from compact_behavior import CONTRACT, EXTRACTOR, FEATURES, FIVE
from compact_behavior.store import Store, stream_lock, ALL
from compact_behavior.extract import digest
from . import MODEL, REFERENCE_WINDOWS
from .engine import summarize, evaluate


class ChangedDuringAnalysis(Exception):
    pass


class AnalysisStore(Store):
    def __init__(
        self, config, *, schema="p24_compact_v2", ad_schema="p24_compact_ad_v2"
    ):
        if not re.fullmatch(r"p24_compact_ad(?:_[a-z0-9_]{1,32})?", ad_schema):
            raise ValueError("compact_ad_schema_required")
        super().__init__(config, schema=schema, application="analysis")
        self.ad_schema = ad_schema
        self.iteration = 0

    def init(self):
        super().init()
        s = self.ad_schema
        with self.conn.transaction():
            self.conn.execute(
                "SELECT pg_advisory_xact_lock(%s)", (stream_lock("schema:" + s),)
            )
            for sql in [
                f"CREATE SCHEMA IF NOT EXISTS {s}",
                f"""CREATE TABLE IF NOT EXISTS {s}.window_results(stream_id TEXT NOT NULL,start_ns BIGINT NOT NULL,
                    summary JSONB NOT NULL,summary_hash TEXT NOT NULL,readiness JSONB NOT NULL,
                    feature_version TEXT NOT NULL,model_version TEXT NOT NULL,source_epoch BIGINT NOT NULL,
                    source_published_ns BIGINT NOT NULL,first_source_ns BIGINT NOT NULL,first_analyzed_ns BIGINT NOT NULL,work_cause_ns BIGINT NOT NULL,analyzed_at_ns BIGINT NOT NULL,analysis_seconds DOUBLE PRECISION NOT NULL,
                    revision BIGINT NOT NULL DEFAULT 1,PRIMARY KEY(stream_id,start_ns))""",
                f"""CREATE TABLE IF NOT EXISTS {s}.reference_epochs(stream_id TEXT PRIMARY KEY,epoch BIGINT NOT NULL DEFAULT 0)""",
                f"""CREATE TABLE IF NOT EXISTS {s}.summary_history(stream_id TEXT NOT NULL,start_ns BIGINT NOT NULL,summary_hash TEXT NOT NULL,
                    feature_version TEXT NOT NULL,model_version TEXT NOT NULL,summary JSONB NOT NULL,recorded_at_ns BIGINT NOT NULL,
                    PRIMARY KEY(stream_id,start_ns,summary_hash,feature_version,model_version))""",
                f"""CREATE TABLE IF NOT EXISTS {s}.reanalysis(stream_id TEXT NOT NULL,start_ns BIGINT NOT NULL,
                    version BIGINT NOT NULL DEFAULT 1,updated_at_ns BIGINT NOT NULL DEFAULT 0,processed_version BIGINT NOT NULL DEFAULT 0,
                    PRIMARY KEY(stream_id,start_ns))""",
                f"CREATE INDEX IF NOT EXISTS compact_reanalysis_ready ON {s}.reanalysis(stream_id,start_ns) WHERE processed_version<version",
                f"""CREATE TABLE IF NOT EXISTS {s}.findings(finding_id TEXT PRIMARY KEY,stream_id TEXT NOT NULL,
                    start_ns BIGINT NOT NULL,method TEXT NOT NULL,service TEXT NOT NULL,session_id TEXT,
                    status TEXT NOT NULL,result JSONB NOT NULL,result_hash TEXT NOT NULL,revision BIGINT NOT NULL DEFAULT 1,
                    first_seen_ns BIGINT NOT NULL,updated_at_ns BIGINT NOT NULL)""",
                f"CREATE INDEX IF NOT EXISTS compact_finding_status ON {s}.findings(stream_id,status,start_ns DESC,finding_id)",
                f"""CREATE TABLE IF NOT EXISTS {s}.finding_history(finding_id TEXT NOT NULL,revision BIGINT NOT NULL,
                    result JSONB NOT NULL,recorded_at_ns BIGINT NOT NULL,PRIMARY KEY(finding_id,revision))""",
                f"""CREATE TABLE IF NOT EXISTS {s}.feedback(feedback_id BIGSERIAL PRIMARY KEY,finding_id TEXT NOT NULL,
                    finding_revision BIGINT NOT NULL,verdict TEXT NOT NULL,note TEXT NOT NULL,recorded_at_ns BIGINT NOT NULL)""",
                f"CREATE INDEX IF NOT EXISTS compact_feedback_finding ON {s}.feedback(finding_id,feedback_id)",
            ]:
                self.conn.execute(sql)

    def select_work(self, stream):
        self.iteration += 1
        s = self.schema
        a = self.ad_schema
        # Live freshness gets four slots; one slot guarantees old/reference work.
        direction = "ASC" if self.iteration % 5 == 0 else "DESC"
        row = self.conn.execute(
            f"""SELECT start_ns FROM(
            SELECT start_ns FROM {s}.dirty_windows WHERE stream_id=%s AND session_id=%s AND processed_version<version
            UNION SELECT start_ns FROM {a}.reanalysis WHERE stream_id=%s AND processed_version<version
            ) x ORDER BY start_ns {direction} LIMIT 1""",
            (stream, ALL, stream),
        ).fetchone()
        return row["start_ns"] if row else None

    def snapshot(self, stream, start):
        s = self.schema
        a = self.ad_schema
        with self.conn.transaction():
            self.conn.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            source = self.conn.execute(
                f"SELECT * FROM {s}.streams WHERE stream_id=%s", (stream,)
            ).fetchone()
            if not source or (
                source["contract"],
                source["extractor"],
                source["feature_version"],
            ) != (CONTRACT, EXTRACTOR, FEATURES):
                raise ValueError("compact_analysis_contract_mismatch")
            reference_epoch = self.conn.execute(
                f"SELECT epoch FROM {a}.reference_epochs WHERE stream_id=%s", (stream,)
            ).fetchone()
            dirty = self.conn.execute(
                f"""SELECT session_id,version,updated_at_ns FROM {s}.dirty_windows
                WHERE stream_id=%s AND start_ns=%s AND processed_version<version ORDER BY session_id""",
                (stream, start),
            ).fetchall()
            job = self.conn.execute(
                f"SELECT version,updated_at_ns FROM {a}.reanalysis WHERE stream_id=%s AND start_ns=%s",
                (stream, start),
            ).fetchone()
            published = self.conn.execute(
                f"SELECT published_at_ns,first_published_ns FROM {s}.windows WHERE stream_id=%s AND start_ns=%s",
                (stream, start),
            ).fetchone()
            if not published:
                raise ValueError("target_window_not_published")
            # Only already analyzed, strictly prior event windows, bounded to 24h.
            # A missing/dirty reference never becomes a silent zero observation.
            refs = self.conn.execute(
                f"""SELECT r.start_ns,r.summary,r.summary_hash,r.revision FROM {a}.window_results r
                WHERE r.stream_id=%s AND r.start_ns>=%s AND r.start_ns<%s AND r.feature_version=%s AND r.model_version=%s
                AND NOT EXISTS(SELECT 1 FROM {s}.dirty_windows d WHERE d.stream_id=r.stream_id AND d.start_ns=r.start_ns
                AND d.session_id=%s AND d.processed_version<d.version)
                AND NOT EXISTS(SELECT 1 FROM {a}.reanalysis j WHERE j.stream_id=r.stream_id AND j.start_ns=r.start_ns
                AND j.processed_version<j.version) ORDER BY r.start_ns""",
                (stream, start - REFERENCE_WINDOWS * FIVE, start, FEATURES, MODEL, ALL),
            ).fetchall()
            with self.conn.cursor(name="compact_analysis_input") as cur:
                cur.itersize = 1000
                cur.execute(
                    f"""SELECT behavior_id,session_id,result_code,features,kind FROM {s}.behaviors
                    WHERE stream_id=%s AND observed_at_ns>=%s AND observed_at_ns<%s ORDER BY observed_at_ns,behavior_id""",
                    (stream, start, start + FIVE),
                )
                summary, services, actors = summarize(cur, cutoff_ns=start + FIVE)
        return dict(
            stream=stream,
            start=start,
            reference_epoch=reference_epoch["epoch"] if reference_epoch else 0,
            epoch=source["change_epoch"],
            dirty=dirty,
            job=job,
            published_at_ns=published["published_at_ns"],
            first_published_ns=published["first_published_ns"],
            cause_ns=max(
                [published["published_at_ns"]]
                + [d["updated_at_ns"] for d in dirty]
                + ([job["updated_at_ns"]] if job else [])
            ),
            summary=summary,
            services=services,
            actors=actors,
            references=refs,
        )

    def commit_analysis(self, work, results, seconds, *, fault=None):
        from psycopg.types.json import Jsonb

        s = self.schema
        a = self.ad_schema
        stream = work["stream"]
        start = work["start"]
        now = time.time_ns()
        summary = work["summary"]
        signature = digest(summary)
        counts = {}
        for method in sorted({r["method"] for r in results}):
            counts[method] = dict(
                Counter(r["status"] for r in results if r["method"] == method)
            )
        with self.conn.transaction():
            self.conn.execute(
                "SELECT pg_advisory_xact_lock(%s)", (stream_lock(stream),)
            )
            epoch = self.conn.execute(
                f"SELECT change_epoch FROM {s}.streams WHERE stream_id=%s", (stream,)
            ).fetchone()
            if not epoch or epoch["change_epoch"] != work["epoch"]:
                raise ChangedDuringAnalysis("source_changed_during_analysis")
            reference_epoch = self.conn.execute(
                f"SELECT epoch FROM {a}.reference_epochs WHERE stream_id=%s", (stream,)
            ).fetchone()
            if (reference_epoch["epoch"] if reference_epoch else 0) != work[
                "reference_epoch"
            ]:
                raise ChangedDuringAnalysis("reference_summary_changed_during_analysis")
            observed = self.conn.execute(
                f"""SELECT session_id,version,updated_at_ns FROM {s}.dirty_windows WHERE stream_id=%s
                AND start_ns=%s AND processed_version<version ORDER BY session_id""",
                (stream, start),
            ).fetchall()
            if observed != work["dirty"]:
                raise ChangedDuringAnalysis("dirty_version_changed")
            job = self.conn.execute(
                f"SELECT version,updated_at_ns FROM {a}.reanalysis WHERE stream_id=%s AND start_ns=%s",
                (stream, start),
            ).fetchone()
            if job != work["job"]:
                raise ChangedDuringAnalysis("reference_revision_changed")
            before = self.conn.execute(
                f"SELECT summary_hash FROM {a}.window_results WHERE stream_id=%s AND start_ns=%s",
                (stream, start),
            ).fetchone()
            self.conn.execute(
                f"""INSERT INTO {a}.window_results(stream_id,start_ns,summary,summary_hash,readiness,feature_version,
                model_version,source_epoch,source_published_ns,first_source_ns,first_analyzed_ns,work_cause_ns,analyzed_at_ns,analysis_seconds) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(stream_id,start_ns) DO UPDATE SET summary=excluded.summary,summary_hash=excluded.summary_hash,
                readiness=excluded.readiness,feature_version=excluded.feature_version,model_version=excluded.model_version,
                source_epoch=excluded.source_epoch,source_published_ns=excluded.source_published_ns,analyzed_at_ns=excluded.analyzed_at_ns,
                analysis_seconds=excluded.analysis_seconds,work_cause_ns=excluded.work_cause_ns,revision={a}.window_results.revision+1""",
                (
                    stream,
                    start,
                    Jsonb(summary),
                    signature,
                    Jsonb(counts),
                    FEATURES,
                    MODEL,
                    work["epoch"],
                    work["published_at_ns"],
                    work["first_published_ns"],
                    now,
                    work["cause_ns"],
                    now,
                    seconds,
                ),
            )
            previous = {
                r["finding_id"]: r
                for r in self.conn.execute(
                    f"SELECT * FROM {a}.findings WHERE stream_id=%s AND start_ns=%s",
                    (stream, start),
                )
            }
            next_results = {
                digest(
                    [
                        FEATURES,
                        MODEL,
                        stream,
                        start,
                        r["method"],
                        r["service"],
                        r["session_id"],
                        r.get("numeric_path"),
                    ]
                ): r
                for r in results
            }
            for key, old in previous.items():
                if key not in next_results:
                    result = dict(
                        old["result"],
                        status="INVALID_INPUT",
                        reason="OBSERVATION_REMOVED_OR_NO_LONGER_ELIGIBLE",
                    )
                    next_results[key] = result
            for key, result in next_results.items():
                old = previous.get(key)
                if not old and result["status"] != "ANOMALY":
                    continue
                result_hash = digest(result)
                if old and old["result_hash"] == result_hash:
                    continue
                revision = old["revision"] + 1 if old else 1
                self.conn.execute(
                    f"""INSERT INTO {a}.findings VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT(finding_id) DO UPDATE SET status=excluded.status,result=excluded.result,result_hash=excluded.result_hash,
                    revision=excluded.revision,updated_at_ns=excluded.updated_at_ns""",
                    (
                        key,
                        stream,
                        start,
                        result["method"],
                        result["service"],
                        result["session_id"],
                        result["status"],
                        Jsonb(result),
                        result_hash,
                        revision,
                        old["first_seen_ns"] if old else now,
                        now,
                    ),
                )
                self.conn.execute(
                    f"INSERT INTO {a}.finding_history VALUES(%s,%s,%s,%s)",
                    (key, revision, Jsonb(result), now),
                )
            # Dirty ACK and results are one transaction. The stream fence also
            # prevents an ABA after retention and a concurrent writer revision.
            acknowledged = self.conn.execute(
                f"""UPDATE {s}.dirty_windows SET processed_version=version WHERE stream_id=%s
                AND start_ns=%s AND processed_version<version""",
                (stream, start),
            ).rowcount
            self.conn.execute(
                f"UPDATE {s}.queue_counts SET dirty_keys=dirty_keys-%s WHERE stream_id=%s",
                (acknowledged, stream),
            )
            self.conn.execute(
                f"UPDATE {a}.reanalysis SET processed_version=version WHERE stream_id=%s AND start_ns=%s",
                (stream, start),
            )
            if not before or before["summary_hash"] != signature:
                self.conn.execute(
                    f"INSERT INTO {a}.reference_epochs VALUES(%s,1) ON CONFLICT(stream_id) DO UPDATE SET epoch={a}.reference_epochs.epoch+1",
                    (stream,),
                )
                self.conn.execute(
                    f"INSERT INTO {a}.summary_history VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                    (stream, start, signature, FEATURES, MODEL, Jsonb(summary), now),
                )
                # Only target windows that actually used this event-time range.
                # No raw/request scans; unique bounded reanalysis keys, not jobs
                # appended for every fragment.
                self.conn.execute(
                    f"""INSERT INTO {a}.reanalysis(stream_id,start_ns,updated_at_ns) SELECT stream_id,start_ns,%s
                    FROM {a}.window_results WHERE stream_id=%s AND start_ns>%s AND start_ns<=%s
                    ON CONFLICT(stream_id,start_ns) DO UPDATE SET version={a}.reanalysis.version+1,updated_at_ns=excluded.updated_at_ns""",
                    (now, stream, start, start + REFERENCE_WINDOWS * FIVE),
                )
            # Completed reanalysis metadata is not an ever-growing ready queue.
            self.conn.execute(
                f"""DELETE FROM {a}.reanalysis WHERE stream_id=%s AND processed_version=version AND start_ns<%s""",
                (stream, start - REFERENCE_WINDOWS * FIVE),
            )
            if fault:
                fault("before_commit")
        if fault:
            fault("after_commit")
        return dict(
            status="ANALYSIS_COMMITTED",
            start_ns=start,
            counts=counts,
            anomalies=sum(r["status"] == "ANOMALY" for r in results),
            source_epoch=work["epoch"],
            analysis_seconds=seconds,
            publication_to_analysis_seconds=(now - work["cause_ns"]) / 1e9,
            reference_windows=len(work["references"]),
        )

    def step(self, stream, *, fault=None):
        start = self.select_work(stream)
        if start is None:
            return dict(status="ANALYSIS_IDLE")
        began = time.monotonic()
        work = self.snapshot(stream, start)
        results = evaluate(
            start, work["summary"], work["services"], work["actors"], work["references"]
        )
        return self.commit_analysis(
            work, results, time.monotonic() - began, fault=fault
        )
