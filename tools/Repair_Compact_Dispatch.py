"""Review one dispatcher binding; --apply rereads only its complete published window."""
import argparse
from pathlib import Path
import sys
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project', type=Path, required=True)
    p.add_argument('--code-root', type=Path, required=True)
    p.add_argument('--expected-source-sha', required=True)
    p.add_argument('--request-id', required=True)
    p.add_argument('--service', required=True)
    p.add_argument('--apply', action='store_true')
    a = p.parse_args(); sys.path.insert(0, str(a.code_root.resolve()))
    from compact_product.version import verify
    from compact_product.config import load
    from compact_product.dispatch_review import inspect, DispatchWindowWriter
    from compact_behavior import FIVE
    from compact_behavior.store import Store
    from compact_behavior.source import ElasticWindow
    from compact_behavior.__main__ import measure_window, save, notice
    output = a.project/'AnomalyDetection/reports'/('Compact_Dispatch_Repair_'+time.strftime('%Y%m%d_%H%M%S')+'.json')
    report = dict(status='COMPACT_DISPATCH_REVIEW_STARTED', database_modified=False,
                  workers_restarted=False, source_contacted=False, data_reset=False)
    db = None
    try:
        package = verify(a.code_root)
        if package['source_sha256'] != a.expected_source_sha:
            raise ValueError('release_hash_mismatch')
        report['package'] = package
        cfg, settings, stream = load(a.project)
        db = Store(settings['DATABASE'], schema=cfg.source_schema, application='dispatch-review')
        with db.conn.transaction():
            db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            report['before'] = inspect(db, stream, a.request_id, a.service)
        if a.apply and not report['before']['ready_for_rate_analysis']:
            start = report['before']['start_ns']; report['source_contacted'] = True
            save(output, report)
            source = ElasticWindow(settings['ELASTICSEARCH'], start, start+FIVE,
                page_size=settings['ELASTICSEARCH'].get('compact_page_size',500), budget=cfg.ingest_budget_seconds)
            report['repair'] = measure_window(DispatchWindowWriter(db,a.request_id,a.service,start),
                stream, source, progress=lambda **kw: notice('COMPACT_DISPATCH_WINDOW_READING',**kw))
            report['database_modified'] = True
        with db.conn.transaction():
            db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            report['after'] = inspect(db, stream, a.request_id, a.service)
        report['status'] = ('COMPACT_DISPATCH_REPAIRED_ANALYSIS_REFRESH_REQUESTED'
            if report['database_modified'] else 'COMPACT_DISPATCH_ALREADY_READY'
            if report['after']['ready_for_rate_analysis'] else 'COMPACT_DISPATCH_REPAIR_REQUIRED')
    except Exception as exc:
        report['status'] = 'COMPACT_DISPATCH_REPAIR_INCOMPLETE'
        report['failure'] = dict(type=type(exc).__name__,sqlstate=getattr(exc,'sqlstate',None),
                                code=str(exc) if isinstance(exc,ValueError) else None)
    finally:
        if db: db.close()
        save(output, report)
        notice(report['status'],output=str(output),database_modified=report['database_modified'],
               workers_restarted=False,data_reset=False)
    return 2 if report['status'].endswith('INCOMPLETE') else 0


if __name__ == '__main__': raise SystemExit(main())
