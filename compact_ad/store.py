"""Snapshot computation, then version-fenced atomic result publication and ACK."""

from collections import Counter
import re
import time
from compact_behavior import CONTRACT, EXTRACTOR, FEATURES, FIVE, postal
from compact_behavior.store import Store, stream_lock, ALL
from compact_behavior.extract import digest
from . import MODEL, REFERENCE_WINDOWS
from .engine import summarize, evaluate
from . import seasonality, long_store, longitudinal
from . import inquiry_breadth, references as reference_inputs
from compact_behavior import security


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
        self.security_migration_cursor = {}

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
                f"ALTER TABLE {s}.window_results ADD COLUMN IF NOT EXISTS timing_confirmed_revision BIGINT NOT NULL DEFAULT 0, ADD COLUMN IF NOT EXISTS postal_health JSONB",
                f"CREATE INDEX IF NOT EXISTS compact_analysis_model ON {s}.window_results(stream_id,model_version,feature_version)",
                f"""CREATE TABLE IF NOT EXISTS {s}.reference_epochs(stream_id TEXT PRIMARY KEY,epoch BIGINT NOT NULL DEFAULT 0)""",
                f"""CREATE TABLE IF NOT EXISTS {s}.summary_history(stream_id TEXT NOT NULL,start_ns BIGINT NOT NULL,summary_hash TEXT NOT NULL,
                    feature_version TEXT NOT NULL,model_version TEXT NOT NULL,summary JSONB NOT NULL,recorded_at_ns BIGINT NOT NULL,
                    PRIMARY KEY(stream_id,start_ns,summary_hash,feature_version,model_version))""",
                f"""CREATE TABLE IF NOT EXISTS {s}.reanalysis(stream_id TEXT NOT NULL,start_ns BIGINT NOT NULL,
                    version BIGINT NOT NULL DEFAULT 1,updated_at_ns BIGINT NOT NULL DEFAULT 0,processed_version BIGINT NOT NULL DEFAULT 0,
                    PRIMARY KEY(stream_id,start_ns))""",
                f"ALTER TABLE {s}.reanalysis ADD COLUMN IF NOT EXISTS priority BOOLEAN NOT NULL DEFAULT false",
                f"CREATE INDEX IF NOT EXISTS compact_requested_reanalysis ON {s}.reanalysis(stream_id,start_ns) WHERE priority AND processed_version<version",
                f"CREATE INDEX IF NOT EXISTS compact_revision_timing_unconfirmed ON {s}.window_results(stream_id,start_ns) WHERE timing_confirmed_revision<>revision",
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
            seasonality.initialize(self.conn, s)
            long_store.initialize(self.conn, s)

    def queue_security_migration(self, stream):
        # Only this analysis lease writes results. New results always carry the
        # current policy, so a forward cursor is sufficient for pre-upgrade
        # summaries. Once caught up, do not detoast all historical JSON again
        # on every idle/live iteration. A restarted analyzer checks afresh.
        cursor = self.security_migration_cursor.get(stream, 'START')
        if cursor == 'DONE':
            return
        lower = '' if cursor == 'START' else 'AND r.start_ns>%s'
        args = [time.time_ns(), stream, FEATURES, MODEL, security.POLICY,inquiry_breadth.POLICY,reference_inputs.POLICY]
        if cursor != 'START':
            args.append(cursor)
        row = self.conn.execute(f'''INSERT INTO {self.ad_schema}.reanalysis(stream_id,start_ns,updated_at_ns)
            SELECT r.stream_id,r.start_ns,%s FROM {self.ad_schema}.window_results r
            WHERE r.stream_id=%s AND r.feature_version=%s AND r.model_version=%s
            AND (COALESCE(r.summary->'security'->>'policy','')<>%s
                OR COALESCE(r.summary->>'inquiry_policy','')<>%s
                OR COALESCE(r.summary->>'analysis_policy','')<>%s) {lower}
            AND NOT EXISTS(SELECT 1 FROM {self.ad_schema}.reanalysis j WHERE j.stream_id=r.stream_id
                AND j.start_ns=r.start_ns AND j.processed_version<j.version)
            ORDER BY r.start_ns ASC LIMIT 1
            ON CONFLICT(stream_id,start_ns) DO UPDATE SET version={self.ad_schema}.reanalysis.version+1,updated_at_ns=excluded.updated_at_ns
            RETURNING start_ns''', args).fetchone()
        self.security_migration_cursor[stream] = row['start_ns'] if row else 'DONE'

    def select_work(self, stream):
        self.iteration += 1
        s = self.schema
        a = self.ad_schema
        # Rebuild every previously analyzed window, one job per iteration.
        # A model upgrade must not leave completed historical ranges on old AD.
        # Existing results/history/feedback remain available as old revisions.
        self.conn.execute(
            f"""INSERT INTO {a}.reanalysis(stream_id,start_ns,updated_at_ns)
            SELECT r.stream_id,r.start_ns,%s FROM {a}.window_results r
            WHERE r.stream_id=%s AND (r.feature_version<>%s OR r.model_version<>%s)
            AND NOT EXISTS(SELECT 1 FROM {a}.reanalysis j WHERE j.stream_id=r.stream_id
                AND j.start_ns=r.start_ns AND j.processed_version<j.version)
            ORDER BY r.start_ns ASC LIMIT 1
            ON CONFLICT(stream_id,start_ns) DO UPDATE SET version={a}.reanalysis.version+1,updated_at_ns=excluded.updated_at_ns""",
            (time.time_ns(), stream, FEATURES, MODEL),
        )
        self.queue_security_migration(stream)
        # A directly evidenced case must not sit behind weeks of unrelated
        # policy warm-up. Bound this slice; ordinary history retains four turns.
        if self.iteration % 5 == 0:
            requested=self.conn.execute(f'''SELECT start_ns FROM {a}.reanalysis WHERE stream_id=%s
                AND priority AND processed_version<version ORDER BY start_ns LIMIT 1''',(stream,)).fetchone()
            if requested:
                return requested['start_ns']
            candidate = self.conn.execute(f'''WITH candidates AS MATERIALIZED (
                SELECT stream_id,start_ns FROM {a}.findings WHERE stream_id=%s AND status='ANOMALY'
                AND result->>'single_signal_review_eligible'='true'
                AND method IN ('repeated_target','target_diversity','access_denied_attempts','invalid_session_attempts')
                ORDER BY start_ns DESC,finding_id DESC LIMIT 64)
                SELECT c.start_ns FROM candidates c JOIN {a}.window_results r USING(stream_id,start_ns)
                LEFT JOIN {a}.reanalysis j USING(stream_id,start_ns)
                WHERE COALESCE(r.summary->>'analysis_policy','')<>%s OR j.processed_version<j.version
                ORDER BY c.start_ns DESC LIMIT 1''', (stream,reference_inputs.POLICY)).fetchone()
            if candidate:
                self.conn.execute(f'''INSERT INTO {a}.reanalysis(stream_id,start_ns,updated_at_ns) VALUES(%s,%s,%s)
                    ON CONFLICT(stream_id,start_ns) DO UPDATE SET version={a}.reanalysis.version+1,updated_at_ns=excluded.updated_at_ns
                    WHERE {a}.reanalysis.processed_version={a}.reanalysis.version''',
                    (stream,candidate['start_ns'],time.time_ns()))
                return candidate['start_ns']
        # Fresh/changed source has priority on four out of five iterations.
        # Reference-only work is chronological: processing newer dependants
        # before their older references repeatedly invalidates the same results.
        # The fifth iteration guarantees progress even with continuous writes.
        if self.iteration % 5:
            fresh = self.conn.execute(
                f"""SELECT start_ns FROM {s}.dirty_windows WHERE stream_id=%s
                AND session_id=%s AND processed_version<version
                ORDER BY start_ns DESC LIMIT 1""", (stream, ALL)
            ).fetchone()
            if fresh:
                return fresh["start_ns"]
        row = self.conn.execute(
            f"""SELECT start_ns FROM(
            SELECT start_ns FROM {s}.dirty_windows WHERE stream_id=%s AND session_id=%s AND processed_version<version
            UNION SELECT start_ns FROM {a}.reanalysis WHERE stream_id=%s AND processed_version<version
            ) x ORDER BY start_ns ASC LIMIT 1""",
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
            long_needed = bool(dirty) or self.conn.execute(f'''SELECT 1 FROM {a}.long_manifest m
                LEFT JOIN {a}.window_results r USING(stream_id,start_ns)
                WHERE m.stream_id=%s AND m.start_ns=%s AND m.published_ns=%s AND m.version=%s
                AND m.base_revision=COALESCE(r.revision,0)''',
                (stream,start,published['published_at_ns'],longitudinal.VERSION)).fetchone() is None
            # Only already analyzed, strictly prior event windows, bounded to 24h.
            # A missing/dirty reference never becomes a silent zero observation.
            refs = self.conn.execute(
                f"""SELECT r.start_ns,r.summary,r.summary_hash,r.revision FROM {a}.window_results r
                WHERE r.stream_id=%s AND r.start_ns>=%s AND r.start_ns<%s AND r.feature_version=%s AND r.model_version=%s
                AND NOT EXISTS(SELECT 1 FROM {s}.dirty_windows d WHERE d.stream_id=r.stream_id AND d.start_ns=r.start_ns
                AND d.session_id=%s AND d.processed_version<d.version)
                AND r.source_published_ns=(SELECT w.published_at_ns FROM {s}.windows w
                    WHERE w.stream_id=r.stream_id AND w.start_ns=r.start_ns)
                AND r.summary->'security'->>'policy'=%s AND r.summary->>'inquiry_policy'=%s
                ORDER BY r.start_ns""",
                (stream, start - REFERENCE_WINDOWS * FIVE, start, FEATURES, MODEL, ALL,security.POLICY,inquiry_breadth.POLICY),
            ).fetchall()
            temporal_refs = self.conn.execute(f'''SELECT h.start_ns,h.rates,h.complete,h.summary_hash
                FROM {a}.rate_history h JOIN {a}.window_results r USING(stream_id,start_ns)
                WHERE h.stream_id=%s AND h.slot=%s AND h.start_ns>=%s AND h.start_ns<%s
                AND h.summary_hash=r.summary_hash AND r.feature_version=%s
                AND NOT EXISTS(SELECT 1 FROM {s}.dirty_windows d WHERE d.stream_id=h.stream_id
                    AND d.start_ns=h.start_ns AND d.session_id=%s AND d.processed_version<d.version)
                AND r.source_published_ns=(SELECT w.published_at_ns FROM {s}.windows w
                    WHERE w.stream_id=r.stream_id AND w.start_ns=r.start_ns)
                AND r.model_version=%s AND r.summary->'security'->>'policy'=%s
                AND r.summary->>'inquiry_policy'=%s
                ORDER BY h.start_ns LIMIT 672''',
                (stream,(start//FIVE)%12,start-seasonality.HORIZON*FIVE,start,FEATURES,ALL,MODEL,security.POLICY,inquiry_breadth.POLICY)).fetchall()
            with self.conn.cursor(name="compact_analysis_input") as cur:
                cur.itersize = 1000
                cur.execute(
                    security.input_sql(s),
                    (stream, start, start + FIVE),
                )
                summary, services, actors = summarize(security.legacy_rows(cur), cutoff_ns=start + FIVE, collect_longitudinal=long_needed)
            active_sessions = Counter()
            for (session,_),actor in actors.items():active_sessions[session] += actor['count']
            candidates = [session for session,count in active_sessions.items() if count>=10]
            candidates=sorted(set(candidates)|{session for session,_ in inquiry_breadth.current(actors)})
            previous_events = None
            previous_inquiries=[]
            if candidates and self.conn.execute(f'SELECT 1 FROM {s}.windows WHERE stream_id=%s AND start_ns=%s',(stream,start-FIVE)).fetchone():
                previous_events = {session: [] for session in candidates}
                with self.conn.cursor(name='compact_previous_events') as previous:
                    previous.itersize=1000
                    previous.execute(security.input_sql(s,previous=True)+' LIMIT 60001',(stream,start-FIVE,start,candidates))
                    for count,event in enumerate(security.legacy_rows(previous),1):
                        if count>60000:
                            previous_events=None;previous_inquiries=[];break
                        f=event['features']
                        event['service']=f.get('service_key');event['eligible']=f.get('session_eligible')
                        observation=inquiry_breadth.previous(event,start+FIVE)
                        if observation:previous_inquiries.append(observation)
                        if f.get('security_attempt') or f.get('rejected_attempt'):
                            continue
                        if event['session_id'] and (event['eligible'] is not True or not event['service']):
                            previous_events[event['session_id']]=None
                        elif event['session_id'] and previous_events.get(event['session_id'],[]) is not None:
                            from collections import deque
                            if isinstance(previous_events[event['session_id']],list):
                                previous_events[event['session_id']]=deque(maxlen=32)
                            previous_events[event['session_id']].append(
                                (event['observed_at_ns'],event['service'],event['behavior_id']))
                if previous_events is not None:
                    previous_events={k:list(v) if v is not None else None for k,v in previous_events.items()}
            from .patterns import patterns
            summary['patterns'], _ = patterns(actors, previous_events, start)
            summary['security']['base_summary_hash'] = digest(reference_inputs.base(summary))
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
            previous_events=previous_events,
            previous_inquiries=previous_inquiries,
            temporal_references=temporal_refs,
            long_needed=long_needed,
        )

    def commit_analysis(self, work, results, seconds, *, fault=None):
        from psycopg.types.json import Jsonb

        commit_began = time.monotonic()
        s = self.schema
        a = self.ad_schema
        stream = work["stream"]
        start = work["start"]
        now = time.time_ns()
        summary = work["summary"]
        signature = digest(summary)
        long_prepared = long_store.prepare(summary, work['actors']) if work.get('long_needed',True) else None
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
                f"SELECT summary_hash,feature_version,model_version,summary FROM {a}.window_results WHERE stream_id=%s AND start_ns=%s",
                (stream, start),
            ).fetchone()
            # Retain a legacy reference token when the actual measurements are
            # identical. A diagnostic/policy migration must not manufacture a
            # finding revision and silently detach its human feedback.
            if (before and before['feature_version']==FEATURES and before['model_version']==MODEL
                    and reference_inputs.base(before['summary'])==reference_inputs.base(summary)):
                prior_token=before['summary'].get('security',{}).get('base_summary_hash')
                if prior_token:
                    summary['security']['base_summary_hash']=prior_token
                    signature=digest(summary)
            committed_revision = self.conn.execute(
                f"""INSERT INTO {a}.window_results(stream_id,start_ns,summary,summary_hash,readiness,feature_version,
                model_version,source_epoch,source_published_ns,first_source_ns,first_analyzed_ns,work_cause_ns,analyzed_at_ns,analysis_seconds,postal_health) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(stream_id,start_ns) DO UPDATE SET summary=excluded.summary,summary_hash=excluded.summary_hash,
                readiness=excluded.readiness,feature_version=excluded.feature_version,model_version=excluded.model_version,
                source_epoch=excluded.source_epoch,source_published_ns=excluded.source_published_ns,analyzed_at_ns=excluded.analyzed_at_ns,
                postal_health=excluded.postal_health || jsonb_build_object('revision',{a}.window_results.revision+1),
                analysis_seconds=excluded.analysis_seconds,work_cause_ns=excluded.work_cause_ns,revision={a}.window_results.revision+1 RETURNING revision""",
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
                    0,
                    work["cause_ns"],
                    now,
                    seconds,
                    Jsonb(dict(work['services'].get(postal.SERVICE, {}).get('postal_health', {}), revision=1)),
                ),
            ).fetchone()["revision"]
            seasonality.save_rates(self.conn,a,stream,start,summary,signature)
            if long_prepared is not None:
                long_store.save(self.conn,a,stream,start,work['published_at_ns'],long_prepared,committed_revision)
            else:
                self.conn.execute(f'''UPDATE {a}.long_manifest SET base_revision=%s
                    WHERE stream_id=%s AND start_ns=%s''',(committed_revision,stream,start))
            previous = {
                r["finding_id"]: r
                for r in self.conn.execute(
                    f"SELECT * FROM {a}.findings WHERE stream_id=%s AND start_ns=%s AND method<>%s",
                    (stream, start, longitudinal.METHOD),
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
                f"UPDATE {a}.reanalysis SET processed_version=version,priority=false WHERE stream_id=%s AND start_ns=%s",
                (stream, start),
            )
            if not before or (before["summary_hash"], before["feature_version"], before["model_version"]) != (signature, FEATURES, MODEL):
                current_hashes=reference_inputs.hashes(summary)
                previous_hashes=reference_inputs.hashes(before['summary']) if before else (None,)*4
                compatible=bool(before and before['feature_version']==FEATURES and before['model_version']==MODEL)
                base_changed=not compatible or previous_hashes[0]!=current_hashes[0]
                rates_changed=not compatible or previous_hashes[1]!=current_hashes[1]
                security_changed=not compatible or previous_hashes[2]!=current_hashes[2]
                rolling_changed=not compatible or previous_hashes[3]!=current_hashes[3]
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
                    AND ((%s AND start_ns<=%s) OR (%s AND (start_ns/{FIVE})%%12=%s)
                        OR (%s AND start_ns=%s))
                    ON CONFLICT(stream_id,start_ns) DO UPDATE SET version={a}.reanalysis.version+1,updated_at_ns=excluded.updated_at_ns
                    WHERE {a}.reanalysis.processed_version={a}.reanalysis.version""",
                    (now, stream, start, start + seasonality.HORIZON*FIVE,
                     base_changed or security_changed,start+REFERENCE_WINDOWS*FIVE,
                     rates_changed,(start//FIVE)%12,rolling_changed,start+FIVE),
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
        # Semantic result + ACK are already durable. Timing is confirmed only
        # after that commit; a crash here leaves 0 (unknown), never a fast SLA.
        confirmed_ns = time.time_ns()
        confirmed = self.conn.execute(
            f"""UPDATE {a}.window_results SET first_analyzed_ns=CASE WHEN first_analyzed_ns=0 THEN %s ELSE first_analyzed_ns END,
            analyzed_at_ns=%s,analysis_seconds=%s,timing_confirmed_revision=revision
            WHERE stream_id=%s AND start_ns=%s AND revision=%s""",
            (
                confirmed_ns,
                confirmed_ns,
                seconds + time.monotonic() - commit_began,
                stream,
                start,
                committed_revision,
            ),
        ).rowcount == 1
        return dict(
            status="ANALYSIS_COMMITTED",
            start_ns=start,
            counts=counts,
            anomalies=sum(r["status"] == "ANOMALY" for r in results),
            source_epoch=work["epoch"],
            analysis_seconds=seconds + time.monotonic() - commit_began,
            publication_to_analysis_seconds=(confirmed_ns - work["cause_ns"]) / 1e9 if confirmed else None,
            timing_confirmed=confirmed,
            reference_windows=len(work["references"]),
        )

    def step(self, stream, *, fault=None):
        began = time.monotonic()
        seasonality.backfill(self.conn,self.ad_schema,stream)
        start = self.select_work(stream)
        # A bounded background unit every tenth iteration (or idle). It never
        # rewrites base results/ACKs, so extension warm-up cannot hold history.
        if start is None or self.iteration % 10 == 0:
            background = long_store.step(self, stream, allow_backfill=start is None)
            if background:
                background['analysis_seconds'] = time.monotonic() - began
                background['total_seconds'] = background['analysis_seconds']
                return background
        if start is None:
            return dict(status="ANALYSIS_IDLE")
        work = self.snapshot(stream, start)
        results = evaluate(
            start, work["summary"], work["services"], work["actors"], work["references"],
            previous_events=work['previous_events'],temporal_references=work['temporal_references']
            ,previous_inquiries=work['previous_inquiries']
        )
        return self.commit_analysis(
            work, results, time.monotonic() - began, fault=fault
        )
