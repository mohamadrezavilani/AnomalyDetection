"""One finite owner probe, including read-only before/after checkpoint checks."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from p24_foundation.viewer_runtime import atomic_json,runtime_source_digest
from p24_foundation.viewer_online import FIVE_NS
from tools.check_viewer_install import check
from tools.viewer_pg_observer import load_viewer_database
from tools.profile_viewer_window import main as profile


def checkpoint(database):
    import psycopg
    opts=dict(database);opts.setdefault('connect_timeout',5)
    with psycopg.connect(**opts) as conn:
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        conn.execute('SET LOCAL statement_timeout=5000')
        with conn.cursor() as cur:
            cur.execute('SELECT next_ns,generation FROM viewer_live_state WHERE id=1')
            row=cur.fetchone()
            if row is None:raise ValueError('live_state_missing')
            cur.execute('SELECT COUNT(*) FROM viewer_live_receipts')
            receipts=cur.fetchone()[0]
        return dict(next_ns=row[0],generation=row[1],receipts=receipts)


def evaluate(before,after,result):
    published=result.get('result',{}).get('status')=='PUBLISHED'
    if published:
        mode=result['result'].get('mode')
        if mode not in ('forward','recheck','manual_recheck'):return False
        expected_next=before['next_ns']+(FIVE_NS if mode=='forward' else 0)
        return (after['next_ns']==expected_next and
                after['generation']>before['generation'] and
                after['receipts']==before['receipts']+1)
    return before==after


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config',type=Path,required=True)
    ap.add_argument('--out',type=Path,default=Path('validation/d2_finalized_probe.json'))
    args=ap.parse_args(argv)
    report=dict(status='STOPPED_BEFORE_INGEST',runtime_source_sha256=runtime_source_digest(),
                native_acceptance='ONE_WINDOW_ONLY',capacity_800k='NOT_PROVEN',production_modified=False)
    try:
        database=load_viewer_database(args.config)
        report['installation']=check(args.config)
        if report['installation']['status']!='READY_TO_START':
            raise ValueError('installation_check_failed')
        report['before']=checkpoint(database)
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'profile.json'
            profile(['--config',str(args.config),'--max-minutes','6','--out',str(output)])
            report['profile']=json.loads(output.read_text(encoding='utf-8'))
        report['after']=checkpoint(database)
        report['checkpoint_consistent']=evaluate(report['before'],report['after'],report['profile'])
        report['status']=report['profile']['status'] if report['checkpoint_consistent'] else 'FAIL_CHECKPOINT'
    except KeyboardInterrupt:
        report['status']='INTERRUPTED'
    except Exception as exc:
        # Never serialize connection errors, config contents, or customer data.
        report['error_type']=type(exc).__name__
        if isinstance(exc,ValueError) and str(exc) in ('installation_check_failed','live_state_missing'):
            report['error_code']=str(exc)
        if 'profile' in report:report['status']='AFTER_STATE_UNAVAILABLE'
    finally:
        atomic_json(args.out,report)
    print(json.dumps(dict(status=report['status'],output=str(args.out))))
    return 0 if report['status']=='PUBLISHED_UNDER_BUDGET' else 2


if __name__=='__main__':raise SystemExit(main())
