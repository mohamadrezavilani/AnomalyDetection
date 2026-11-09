"""Small read-only owner report for one request, payment links and worker startup."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_execution_detail import execution_detail
from p24_foundation.viewer_online import live_status
from p24_foundation.viewer_runtime import runtime_source_digest
from p24_foundation.viewer_display_time import tehran_time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'viewer_config.local.py')
    parser.add_argument('--request-id', required=True)
    args = parser.parse_args()
    if not 1 <= len(args.request_id) <= 160:
        parser.error('RequestID length must be 1..160')
    report = dict(status='RUNNING', runtime_source_sha256=runtime_source_digest(),
                  mode='read_only_single_request', capture_started=False, database_modified=False)
    report['observed_at_utc']=datetime.now(timezone.utc).isoformat()
    report['observed_at_tehran']=tehran_time(report['observed_at_utc'])
    try:
        spec = importlib.util.spec_from_file_location('private_viewer_probe_config', args.config.resolve())
        cfg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cfg)
        if not str(cfg.DATABASE.get('dbname', '')).startswith('p24_design_'):
            raise ValueError('isolated_viewer_database_required')
        keys = Path(cfg.KEYS_PATH).expanduser()
        if not keys.is_absolute():
            keys = ROOT / keys
        if not keys.is_file():
            raise ValueError('existing_keys_required')
        with ViewerDB(config=cfg.DATABASE, keys_path=keys) as db:
            db.sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            setting = int(db.one("SELECT setting FROM pg_settings WHERE name='statement_timeout'")['setting'])
            db.sql("SELECT set_config('statement_timeout', ?, true)", (str(min(setting, 10000) if setting else 10000),))
            binding = db.one('SELECT keys_fingerprint FROM viewer_live_state WHERE id=1')
            if binding and binding['keys_fingerprint'] != db.keys.fingerprint:
                raise ValueError('existing_keys_fingerprint_mismatch')
            report['live'] = live_status(db)
            from p24_foundation.viewer_data import tehran
            report['last_published_windows'] = [dict(mode=r['mode'],generation=r['generation'],
                from_tehran=tehran(r['start_ns']),to_tehran=tehran(r['end_ns']),cycle_seconds=r['cycle_seconds'])
                for r in db.all('SELECT mode,generation,start_ns,end_ns,cycle_seconds FROM viewer_live_receipts ORDER BY published_ns DESC LIMIT 3')]
            report['widget_role'] = db.one("SELECT role,initiation,source,reviewed FROM viewer_service_roles WHERE service_path='Core.v1/UserWidgetsSetDefault'")
            report['live_tehran'] = {k[:-4] + '_tehran': tehran_time(v)
                                     for k, v in report['live'].items() if k.endswith('_utc')}
            card = db.lookup_request(args.request_id)
            if card:
                view = execution_detail(db, card)
                report['request'] = dict(request_id=args.request_id, service=view['service'], invoices=view['invoices'],
                    result=view['result_label'], result_codes=view['result_codes'], incomplete=view['incomplete'],
                    payment_cards=view['payment_cards'], linked_request_count=view['linked_request_count'],
                    stages=[dict(kind=s['kind'], when_tehran=s['when'], title=s['title'], code=s['code'],
                                 status=s['status'], related=s['related'], request_key=s['request_key']) for s in view['steps']])
            else:
                report['request'] = dict(request_id=args.request_id, status='NOT_CAPTURED')
            report['status'] = 'PASS_READ_ONLY_REPORT'
        startup = ROOT / 'validation/viewer_startup.json'
        report['worker_startup'] = json.loads(startup.read_text()) if startup.is_file() else dict(status='NOT_REPORTED')
        report['startup_source_matches_installed'] = report['worker_startup'].get('runtime_source_sha256') == report['runtime_source_sha256']
    except Exception as exc:
        report.update(status='FAILED', error_type=type(exc).__name__, sqlstate=getattr(exc, 'sqlstate', None))
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_') + uuid.uuid4().hex[:8]
    output = ROOT / 'validation' / ('viewer_detail_probe_' + stamp + '.zip')
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('viewer_detail_probe.json', json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps(dict(status=report['status'], output=str(output))))
    return 0 if report['status'] != 'FAILED' else 2


if __name__ == '__main__':
    raise SystemExit(main())
