"""Re-evaluate the published five-minute window containing a reviewed inquiry witness."""
import argparse
import json
from pathlib import Path
import time

from compact_ad.inquiry_patterns import POLICY
from compact_behavior import FIVE
from compact_behavior.__main__ import measure_window, notice
from compact_behavior.extract import instant
from compact_behavior.source import ElasticWindow
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

    def publish(self, stream, start, end, states, count):
        if start != self.start or end != start + FIVE:
            raise ValueError('window_changed')
        with self.db.conn.transaction():
            self.db.conn.execute("SET LOCAL lock_timeout='10s'")
            self.db.conn.execute('SELECT pg_advisory_xact_lock(%s)', (stream_lock(stream),))
            writers(self.db, self.package)
            return republish(self.db, stream, start, end, states, count, [self.request_id])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--witness', required=True)
    parser.add_argument('--service', required=True)
    parser.add_argument('--axis', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    cfg, settings, stream = load(args.project)
    db = Store(settings['DATABASE'], schema=cfg.source_schema, application='inquiry-case-review')
    try:
        result, _ = review(db, stream, args.witness, args.service, args.axis)
        start = instant(result['from_utc'])
        anchor = db.conn.execute(f'SELECT request_id,session_id FROM {db.schema}.behaviors WHERE stream_id=%s AND behavior_id=%s',
                                 (stream,args.witness)).fetchone()
        with db.conn.transaction():
            db.conn.execute('SET TRANSACTION READ ONLY')
            db.conn.execute("SET LOCAL statement_timeout='10s'")
            rows = db.conn.execute(f"""SELECT method,result->>'reason' AS reason,
                result->'requests' AS requests,result->'distinct_targets' AS distinct_targets,
                result->'most_frequent_count' AS most_frequent_count,
                ({case_selection.publishable(cfg)}) AS current_for_review
                FROM {cfg.ad_schema}.findings f WHERE stream_id=%s AND start_ns=%s
                AND f.status='ANOMALY' AND service=%s AND session_id=%s AND result->>'numeric_path'=%s
                AND result->>'inquiry_pattern_policy'=%s""",
                (*case_selection.eligible_args(),stream,start,args.service,anchor['session_id'],args.axis,POLICY)).fetchall()
        notice('INQUIRY_CASE_OBSERVED', stored=result['stored'], reconstructed=result['retained_reconstruction'],
               findings=rows, database_modified=False)
        if not args.apply or rows:
            return 0
        if not result['retained_reconstruction']['distinct_is_exact']:
            raise ValueError('complete_reconstructable_session_required')
        package = verify()['source_sha256']
        writers(db, package)
        if not result['stored']['distinct_is_exact']:
            source = ElasticWindow(settings['ELASTICSEARCH'], start, start+FIVE,
                page_size=settings['ELASTICSEARCH'].get('compact_page_size',500),budget=cfg.ingest_budget_seconds)
            target = ExistingInquiryWindow(db,anchor['request_id'],start,package)
            measure_window(target,stream,source,progress=lambda **kw: notice('READING_ONE_INQUIRY_WINDOW',**kw))
            after, _ = review(db,stream,args.witness,args.service,args.axis)
            if not after['stored']['distinct_is_exact'] or after['stored'] != after['retained_reconstruction']:
                raise ValueError('source_republished_verify_current_coverage')
        with db.conn.transaction():
            db.conn.execute("SET LOCAL lock_timeout='10s'")
            db.conn.execute('SELECT pg_advisory_xact_lock(%s)',(stream_lock(stream),))
            writers(db, package)
            db.conn.execute(f"""INSERT INTO {cfg.ad_schema}.reanalysis AS q(stream_id,start_ns,updated_at_ns)
                VALUES (%s,%s,%s) ON CONFLICT (stream_id,start_ns) DO UPDATE
                SET version=q.version+1,updated_at_ns=excluded.updated_at_ns WHERE q.version=q.processed_version""",
                (stream,start,time.time_ns()))
        notice('INQUIRY_WINDOW_SUBMITTED_TO_AD', windows=1, from_utc=result['from_utc'])
    finally:
        db.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
