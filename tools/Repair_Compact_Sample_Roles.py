"""Re-read at most two complete published windows for proven stale role samples."""
import argparse
import json
from pathlib import Path
import sys
import time
import uuid


def sample_keys(review, stream, package):
    if review.get('status') != 'READ_ONLY_SAMPLE_RECONCILIATION':
        raise ValueError('sample_reconciliation_required')
    if review.get('stream', {}).get('stream_id') != stream:
        raise ValueError('review_stream_mismatch')
    if review.get('diagnostic_package', {}).get('source_sha256') != package['source_sha256']:
        raise ValueError('review_and_installed_package_must_match')
    samples = review.get('samples', [])
    if not 1 <= len(samples) <= 24:
        raise ValueError('bounded_reconciliation_required')
    keys = [r['request_id'] for r in samples]
    if len(set(keys)) != len(keys) or any(uuid.UUID(k).hex != k for k in keys):
        raise ValueError('canonical_unique_request_ids_required')
    return keys


def stale_windows(store, stream, keys):
    from compact_behavior import FIVE
    from compact_behavior.extract import behavior_id
    from compact_behavior.services import operation_role
    rows = store.conn.execute(f'''SELECT request_id,api,observed_at_ns,
        features->>'operation_role' AS role,features->>'service_key' AS service,
        features->>'service_binding' AS binding FROM {store.schema}.behaviors
        WHERE stream_id=%s AND behavior_id=ANY(%s)''',
        (stream, [behavior_id(stream, k) for k in keys])).fetchall()
    windows = {}
    for row in rows:
        if row['role'] != operation_role(row['api'], row['service'], row['binding']):
            if row['observed_at_ns'] is None:
                raise ValueError('stale_behavior_has_no_window')
            start = row['observed_at_ns'] // FIVE * FIVE
            windows.setdefault(start, []).append(row['request_id'])
    if len(windows) > 2:
        raise ValueError('repair_exceeds_two_windows')
    return windows


def republish(store, stream, start, end, states, count, expected):
    """Fence the normal complete-window publisher; never publish sample subsets."""
    from compact_behavior.store import stream_lock
    if not expected or not set(expected).issubset(states):
        raise ValueError('complete_window_missing_expected_requests')
    with store.conn.transaction():
        store.conn.execute('SELECT pg_advisory_xact_lock(%s)', (stream_lock(stream),))
        before = store.cursor(stream)
        existing = store.conn.execute(f'''SELECT end_ns,source_records,extracted_requests
            FROM {store.schema}.windows WHERE stream_id=%s AND start_ns=%s''',
            (stream, start)).fetchone()
        if not existing or existing['end_ns'] != end or before is None or end > before:
            raise ValueError('repair_requires_already_published_window')
        # Do not replace a publication receipt with a diminished source snapshot.
        if count < existing['source_records'] or len(states) < existing['extracted_requests']:
            raise ValueError('source_window_shrank_no_repair_committed')
        result = store.publish(stream, start, end, states, count)
        if store.cursor(stream) != before:
            raise ValueError('repair_must_preserve_input_checkpoint')
        if stale_windows(store, stream, expected):
            raise ValueError('role_repair_not_applied')
    result['input_checkpoint_preserved_in_transaction'] = True
    return result


class ExistingWindowWriter:
    def __init__(self, store, expected):
        self.store, self.expected, self.limits = store, expected, store.limits

    def publish(self, stream, start, end, states, count):
        return republish(self.store, stream, start, end, states, count, self.expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'code-root', 'review'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    sys.path.insert(0, str(args.code_root.resolve()))
    from compact_behavior import FIVE
    from compact_behavior.__main__ import measure_window, save, notice
    from compact_behavior.source import ElasticWindow
    from compact_behavior.store import Store
    from compact_product.config import load
    from compact_product.version import verify
    from Reconcile_Compact_Samples import read_json
    output = args.project / 'AnomalyDetection/reports' / (
        'Compact_Sample_Repair_' + time.strftime('%Y%m%d_%H%M%S') + '.json')
    report = dict(status='COMPACT_SAMPLE_ROLE_REPAIR_STARTED', windows=[],
        workers_restarted=False, data_reset=False, history_task_changed=False,
        analysis_status='NORMAL_AD_WORKER_CONSUMES_CHANGED_REVISIONS',
        scope='At most two COMPLETE source windows; not the whole expired population.')
    store = None
    try:
        cfg, settings, stream = load(args.project)
        report['package'] = verify(args.code_root)
        keys = sample_keys(read_json(args.review), stream, report['package'])
        store = Store(settings['DATABASE'], schema=cfg.source_schema, application='sample-role-repair')
        windows = stale_windows(store, stream, keys)
        report['planned_window_starts_ns'] = sorted(windows)
        save(output, report)
        if args.apply:
            for start, expected in sorted(windows.items()):
                source = ElasticWindow(settings['ELASTICSEARCH'], start, start + FIVE,
                    page_size=settings['ELASTICSEARCH'].get('compact_page_size', 500),
                    budget=cfg.ingest_budget_seconds)
                result = measure_window(ExistingWindowWriter(store, expected), stream, source,
                    progress=lambda **kw: notice('COMPACT_SAMPLE_WINDOW_READING', **kw))
                report['windows'].append(result)
                save(output, report)
            report['status'] = 'COMPACT_SAMPLE_ROLES_REPAIRED' if windows else 'COMPACT_SAMPLE_ROLES_ALREADY_CURRENT'
        else:
            report['status'] = 'COMPACT_SAMPLE_ROLE_REPAIR_PLAN'
        report['remaining_stale_sample_windows'] = len(stale_windows(store, stream, keys))
    except Exception as exc:
        report['status'] = 'COMPACT_SAMPLE_ROLE_REPAIR_INCOMPLETE'
        report['failure'] = dict(type=type(exc).__name__,
            code=str(exc) if isinstance(exc, (ValueError, TimeoutError)) else None,
            sqlstate=getattr(exc, 'sqlstate', None))
    finally:
        if store:
            store.close()
        save(output, report)
        notice(report['status'], output=str(output),
            republished_windows=len(report['windows']),
            remaining_stale_sample_windows=report.get('remaining_stale_sample_windows'),
            workers_restarted=False, data_reset=False)
    return 2 if report['status'].endswith('INCOMPLETE') else 0


if __name__ == '__main__':
    raise SystemExit(main())
