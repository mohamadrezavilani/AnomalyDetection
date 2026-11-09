"""Project only already-captured new correlation emitters since deployment.

Stop Worker/Web first. No ES access, historical replay, raw changes, role changes
or forward-checkpoint movement. All derived differences commit atomically.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import traceback
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from p24_foundation.viewer_data import ViewerDB, utc_ns
from p24_foundation.viewer_online import single_worker
from p24_foundation.viewer_runtime import atomic_json, runtime_source_digest, ProgressConsole
from p24_foundation.viewer_correlation_sync import sync_payment_correlations


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'viewer_config.local.py')
    parser.add_argument('--since-utc', default='2026-10-28T07:30:00Z')
    args = parser.parse_args(argv)
    since = utc_ns(args.since_utc)
    if since is None:
        parser.error('Valid UTC --since-utc required')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_') + uuid.uuid4().hex[:8]
    private = ROOT / 'private/correlation_sync' / stamp
    private.mkdir(parents=True)
    report = dict(status='RUNNING', runtime_source_sha256=runtime_source_digest(ROOT), since_ns=since,
                  live_es='NOT_RUN', capacity='NOT_RUN_OUT_OF_CURRENT_SCOPE')
    console = ProgressConsole(heartbeat_seconds=15, min_interval=5)
    try:
        from tools.check_viewer_install import verify_release
        report['stage'] = 'verify_release'
        report['release'] = verify_release(ROOT)
        if report['release']['status'] != 'PASS':
            raise ValueError('release_bytes_mismatch')
        spec = importlib.util.spec_from_file_location('viewer_correlation_config', args.config.resolve())
        cfg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cfg)
        keys = Path(cfg.KEYS_PATH).expanduser()
        if not keys.is_absolute():
            keys = ROOT / keys
        if not keys.is_file():
            raise ValueError('existing_private_keys_missing')
        opts = dict(keys_path=keys)
        if getattr(cfg, 'SQLITE_OFFLINE_PATH', None):
            opts['sqlite_path'] = ROOT / cfg.SQLITE_OFFLINE_PATH
        else:
            opts['config'] = cfg.DATABASE
        with ViewerDB(**opts) as db:
            db.progress_callback = console.progress
            with single_worker(db, ROOT / 'private/correlation_sync.lock'):
                if not db.sqlite:
                    from tools.qualify_viewer_payment_correlations import qualify
                    report['stage'] = 'small_native_payment_checks'
                    console.progress(dict(stage='small_native_payment_checks'))
                    report['native_functional'] = qualify(cfg.DATABASE, private / 'native_synthetic')
                report['stage'] = 'sync_captured_correlations'
                report.update(sync_payment_correlations(db, since))
        # Verify known real relationships if those RequestIDs are already
        # captured. Later statuses/payments are allowed; no absence is inferred.
        examples = (
            ('2e323998-266e-4626-959d-02dc59bcf482', 'Services.v1/TrafficFinesCarNoDetails'),
            ('83a8d3b3-3556-484d-946c-19de156f52c5', 'Services.v1/WaterBills'),
            ('13cbb05b-c156-4d88-b56a-b62826c6a156', 'Services.v1/CellPhoneBills'),
            ('5609de27-85b0-41ea-94dc-461dd5c221db', 'Services.v1/ElectricBills'),
            ('2d1bea0f-9eb6-45c6-b46e-bcdd7c8166f7', 'Services.v1/MunicipalityCarTollBills'),
        )
        report['known_real_samples'] = []
        report['stage'] = 'verify_known_real_samples_readonly'
        with ViewerDB(**opts) as db:
            if db.sqlite:
                db.sql('BEGIN')
            else:
                db.sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            for raw_id, api in examples:
                card = db.lookup_request(raw_id)
                if card is None:
                    report['known_real_samples'].append(dict(api=api, status='NOT_CAPTURED_YET'))
                    continue
                journey = card.get('service_payments')
                matched = bool(journey and any(source['api'] == api for group in journey['invoices'] for source in group['sources']))
                report['known_real_samples'].append(dict(api=api, status='PASS_SERVICE_LINK' if matched else 'NEEDS_REVIEW',
                    invoice_count=len(journey['invoices']) if journey else 0,
                    payment_keys=journey['unique_payment_count'] if journey else 0))
        report['ui_native_browser'] = 'NOT_RUN'
        report['stage'] = 'complete'
    except Exception as exc:
        (private / 'failure.private.log').write_text(traceback.format_exc(), encoding='utf-8')
        report.update(status='FAILED', error_type=type(exc).__name__, sqlstate=getattr(exc, 'sqlstate', None))
        frames = traceback.extract_tb(exc.__traceback__)
        if frames:
            report['error_location'] = dict(file=Path(frames[-1].filename).name, line=frames[-1].lineno)
        if str(exc) in ('viewer_worker_already_running', 'existing_private_keys_missing',
                        'existing_semantic_index_required', 'existing_keys_fingerprint_mismatch',
                        'correlation_sync_scope_too_large', 'correlation_sync_cursor_changed',
                        'release_bytes_mismatch', 'native_checks_require_assertions'):
            report['error_code'] = str(exc)
    atomic_json(private / 'correlation_sync.json', report)
    atomic_json(ROOT / 'validation/correlation_sync.json', report)
    out = ROOT / 'validation' / ('correlation_sync_' + stamp + '.zip')
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('correlation_sync.json', json.dumps(report, ensure_ascii=True, indent=2))
    console.emit(dict(status=report['status'], output=str(out)))
    console.close()
    return 2 if report['status'] == 'FAILED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
