"""Read-only, privacy-preserving inspection of LC2A behavioral session timeline.

Example:
python tools/inspect_lc2_session_behavior.py --config viewer_config.local.py --session <SessionID>

This tool intentionally reports execution observations, not user clicks,
financial finality, or proof that every source record was imported.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from p24_foundation.viewer_data import ViewerDB,token,tehran


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--session',help='exact raw SessionID; never printed')
    group.add_argument('--session-key',help='internal HMAC session key')
    parser.add_argument('--scan-limit',type=int,default=100)
    parser.add_argument('--after-ns',type=int)
    parser.add_argument('--after-key')
    args=parser.parse_args()
    try:
        config_path=args.config.resolve(strict=True)
        spec=importlib.util.spec_from_file_location('private_viewer_config',config_path)
        config=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(config)
        opts={'keys_path':Path(config.KEYS_PATH).expanduser().resolve()}
        if getattr(config,'SQLITE_OFFLINE_PATH',None):
            opts['sqlite_path']=Path(config.SQLITE_OFFLINE_PATH).expanduser().resolve()
        else:
            db_opts=dict(config.DATABASE)
            if not str(db_opts.get('dbname','')).startswith('p24_design_'):
                raise ValueError('Viewer database guard')
            opts['config']=db_opts
        with ViewerDB(**opts) as db:
            key=(args.session_key if args.session_key else token(db.keys,'session',args.session))
            timeline=db.session_behavior(key,scan_limit=args.scan_limit,
                after_ns=args.after_ns,after_key=args.after_key)
        # Do not expose Session, user identifiers, IP, payment token or raw payload.
        summary=dict(version=timeline['version'],scope=timeline['completeness_scope'],
            candidate_requests_scanned=timeline['candidate_requests_scanned'],
            observed_semantic_execution_count=timeline['observed_semantic_execution_count'],
            observed_service_execution_count=timeline['observed_service_execution_count'],
            observed_user_management_execution_count=timeline['observed_user_management_execution_count'],
            observed_wallet_funding_execution_count=timeline['observed_wallet_funding_execution_count'],
            observed_product_reservation_execution_count=timeline['observed_product_reservation_execution_count'],
            unclassified_facade_candidates=timeline['unclassified_facade_candidates'],
            confirmed_manual_action_count=timeline['confirmed_manual_action_count'],
            candidate_scan_complete=timeline['candidate_scan_complete'],
            all_session_history_loaded=timeline['all_session_history_loaded'],
            has_more=timeline['has_more'],next_cursor=timeline['next_cursor'],
            observations=[dict(occurrence_key=o['occurrence_key'],kind=o['kind'],
                anchor_request_key=o['anchor_request_key'],
                api=o['root_call'].split(' Line:',1)[0],
                observed_at_tehran=tehran(o['anchor_ns']),
                initiation_confirmed=o['customer_initiation_confirmed'],
                provider_or_bank_settlement='NOT_INFERRED')
                for o in timeline['observed_occurrences']],
            read_only=True)
        print(json.dumps(summary,ensure_ascii=False,indent=2))
    except (OSError,ValueError,Exception):
        # This diagnostic intentionally never prints connection exceptions,
        # which can contain credentials. Detailed stacktraces stay local.
        print('LC2B diagnostic failed: verify the isolated Viewer setup and cursor.',file=sys.stderr)
        raise SystemExit(2) from None

if __name__=='__main__':main()
