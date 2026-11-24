"""Re-evaluate the published five-minute window containing a reviewed inquiry witness."""
import argparse
import json
from pathlib import Path
import time

from compact_ad.inquiry_patterns import POLICY
from compact_ad.inquiry_breadth import POLICY as BREADTH_POLICY
from compact_behavior import FIVE
from compact_behavior.__main__ import notice
from compact_behavior.extract import instant
from compact_behavior.store import Store, stream_lock
from compact_product import case_selection
from compact_product.config import load
from compact_product.version import verify
from tools.Review_Compact_Inquiry_Session import review
from tools.Repair_Compact_Sample_Roles import republish


def writers(db, package):
    rows = db.conn.execute(f"""SELECT role,info->'package'->>'source_sha256' AS sha
        FROM {db.schema}.runtime_roles WHERE role IN ('ingest','analysis','history')""").fetchall()
    deployed = {r['role']:r['sha'] for r in rows}
    if any(deployed.get(role) != package for role in ('ingest','analysis','history')):
        raise ValueError('matching_installed_workers_required')


class ExistingInquiryWindow:
    def __init__(self, db, request_id, start, package):
        self.db, self.request_id, self.start, self.package = db, request_id, start, package
        self.limits = db.limits
        self.committed = False
        self.phase = 'NOT_STARTED'

    def publish(self, stream, start, end, states, count):
        if start != self.start or end != start + FIVE:
            raise ValueError('window_changed')
        began = last = time.monotonic()
        notice('PUBLISHING_ONE_INQUIRY_WINDOW', requests=len(states), source_records=count)

        def progress(**values):
            nonlocal last
            now = time.monotonic()
            self.phase = values['phase']
            if now - began > 180:
                raise TimeoutError('inquiry_publication_budget_exceeded')
            if now - last >= 5:
                notice('PUBLISHING_ONE_INQUIRY_WINDOW', elapsed_seconds=round(now-began, 2), **values)
                last = now

        with self.db.conn.transaction():
            self.phase = 'stream_lock'
            self.db.conn.execute("SET LOCAL lock_timeout='10s'")
            self.db.conn.execute('SELECT pg_advisory_xact_lock(%s)', (stream_lock(stream),))
            writers(self.db, self.package)
            result = republish(self.db, stream, start, end, states, count, [self.request_id], progress=progress)
        self.committed = True
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--witness', required=True)
    parser.add_argument('--service', required=True)
    parser.add_argument('--axis', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    cfg, settings, stream = load(args.project)
    db = None
    target = None
    stage = 'CONNECTING'
    reanalysis_requested = False
    try:
        db = Store(settings['DATABASE'], schema=cfg.source_schema, application='inquiry-case-review')
        stage = 'REVIEWING_RETAINED_INQUIRY'
        result, _ = review(db, stream, args.witness, args.service, args.axis)
        start = instant(result['from_utc'])
        anchor = db.conn.execute(f'SELECT request_id,session_id FROM {db.schema}.behaviors WHERE stream_id=%s AND behavior_id=%s',
                                 (stream,args.witness)).fetchone()
        stage = 'READING_CURRENT_FINDINGS'
        with db.conn.transaction():
            db.conn.execute('SET TRANSACTION READ ONLY')
            db.conn.execute("SET LOCAL statement_timeout='10s'")
            rows = db.conn.execute(f"""SELECT finding_id,method,result->>'reason' AS reason,
                result->'requests' AS requests,result->'distinct_targets' AS distinct_targets,
                result->'most_frequent_count' AS most_frequent_count,
                ({case_selection.publishable(cfg)}) AS current_for_review,
                (SELECT v.verdict FROM {cfg.ad_schema}.feedback v WHERE v.finding_id=f.finding_id
                    AND v.finding_revision=f.revision ORDER BY feedback_id DESC LIMIT 1) AS verdict,
                (SELECT r.timing_confirmed_revision=r.revision FROM {cfg.ad_schema}.window_results r
                    WHERE r.stream_id=f.stream_id AND r.start_ns=f.start_ns) AS timing_confirmed,
                (SELECT r.summary->>'analysis_policy' FROM {cfg.ad_schema}.window_results r
                    WHERE r.stream_id=f.stream_id AND r.start_ns=f.start_ns) AS analysis_policy,
                EXISTS(SELECT 1 FROM {cfg.ad_schema}.reanalysis j WHERE j.stream_id=f.stream_id
                    AND j.start_ns=f.start_ns AND j.processed_version<j.version) AS own_reanalysis_pending
                FROM {cfg.ad_schema}.findings f WHERE stream_id=%s AND start_ns=%s
                AND f.status='ANOMALY' AND service=%s AND session_id=%s AND result->>'numeric_path'=%s
                AND (result->>'inquiry_pattern_policy'=%s OR result->>'inquiry_breadth_policy'=%s)""",
                (*case_selection.eligible_args(),stream,start,args.service,anchor['session_id'],args.axis,POLICY,BREADTH_POLICY)).fetchall()
            selected,_,truncated=case_selection.select(db.conn,cfg,stream,start,start+FIVE)
            visible={f['finding_id'] for c in selected for f in c['findings']}
            for row in rows:row['current_for_review']=bool(row['current_for_review'] and row['finding_id'] in visible)
        human_rejected=bool(rows and all(r['verdict']=='FALSE_POSITIVE' for r in rows))
        ready=any(r['current_for_review'] for r in rows)
        review_state=('VISIBLE_OPERATOR_CASE' if ready else 'REJECTED_BY_REVIEWER' if human_rejected
            else 'WAITING_FOR_TIMING_CONFIRMATION' if rows and any(r['timing_confirmed'] is False for r in rows)
            else 'NEEDS_REANALYSIS')
        notice('INQUIRY_CASE_OBSERVED', stored=result['stored'], reconstructed=result['retained_reconstruction'],
               findings=rows, review_state=review_state,selection_truncated=truncated,database_modified=False)
        if not args.apply or ready or human_rejected:
            return 0
        if not result['retained_reconstruction']['covered']:
            raise ValueError('no_reconstructable_inquiry_subjects')
        package = verify()['source_sha256']
        stage = 'CHECKING_INSTALLED_WRITERS'
        writers(db, package)
        # The analysis reader reconstructs legacy subjects from retained
        # same-request evidence. A stale projection needs one AD job, not an
        # Elasticsearch replay of the entire source window.
        stage = 'SUBMITTING_WINDOW_TO_AD'
        with db.conn.transaction():
            db.conn.execute("SET LOCAL lock_timeout='10s'")
            db.conn.execute('SELECT pg_advisory_xact_lock(%s)',(stream_lock(stream),))
            writers(db, package)
            db.conn.execute(f"""INSERT INTO {cfg.ad_schema}.reanalysis AS q(stream_id,start_ns,updated_at_ns,priority)
                VALUES (%s,%s,%s,true) ON CONFLICT (stream_id,start_ns) DO UPDATE
                SET priority=true,version=q.version+CASE WHEN q.version=q.processed_version THEN 1 ELSE 0 END,
                updated_at_ns=CASE WHEN q.version=q.processed_version THEN excluded.updated_at_ns ELSE q.updated_at_ns END""",
                (stream,start,time.time_ns()))
        reanalysis_requested = True
        notice('INQUIRY_WINDOW_SUBMITTED_TO_AD', windows=1, from_utc=result['from_utc'],
               review_state='REANALYSIS_PENDING',database_modified=True)
    except Exception as exc:
        notice('INQUIRY_CASE_REFRESH_INCOMPLETE', stage=stage,
               failure_type=type(exc).__name__, sqlstate=getattr(exc, 'sqlstate', None),
               code=str(exc) if isinstance(exc, (ValueError, TimeoutError)) else None,
               publication_phase=target.phase if target else None,
               source_window_republished=bool(target and target.committed),
               reanalysis_requested=reanalysis_requested)
        return 2
    finally:
        if db:
            db.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
