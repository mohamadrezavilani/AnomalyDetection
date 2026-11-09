"""Read-only diagnostic for isolated p24_design_* Viewer service journeys.

Does not print raw payloads, payment references, customer identifiers, or tokens.
Examples:
    python tools/inspect_r6_s1b_journeys.py --config viewer_config.local.py
    python tools/inspect_r6_s1b_journeys.py --config viewer_config.local.py --request-id <GUID>
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from time import perf_counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from p24_foundation.viewer_data import ViewerDB

SAMPLES = (
    '0de3da81-0032-45d0-bd73-21067f1c07df',  # gateway callback
    '6ee45e41-7845-478d-b502-82d38a693e5e',  # traffic fines inquiry
    '04cabcb6-ff98-4bab-97ec-c1eb5677355b',  # top-up wallet payment
)


def config_options(config_path):
    if not config_path.is_file():
        raise ValueError('Configuration file not found')
    spec = importlib.util.spec_from_file_location('private_viewer_config', config_path.resolve())
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    keypath = Path(mod.KEYS_PATH).expanduser().resolve()
    if getattr(mod, 'SQLITE_OFFLINE_PATH', None):
        return {'sqlite_path': Path(mod.SQLITE_OFFLINE_PATH), 'keys_path':keypath}
    db = dict(mod.DATABASE)
    if not str(db.get('dbname','')).startswith('p24_design_'):
        raise ValueError('Guard: diagnostic must target isolated p24_design_* database')
    return {'config':db, 'keys_path':keypath}


def summarize(db, request_id):
    match=db.lookup_request(request_id)
    if not match:
        return {'request_id':request_id,'status':'NOT_FOUND_IN_VIEWER'}
    t0=perf_counter()
    journey=db.service_journey(match['request_key'])
    duration=round((perf_counter()-t0)*1000, 2)
    safe_axes = {'provider_response_code','provider_financial_observation',
        'provider_purchase_financial_observation','fulfillment_report',
        'internal_payment_stage_report','platform_reported_result',
        'purchase_notification','bill_item_notification'}
    # Only approved symbolic state values. Arbitrary log text never printed.
    def masked_status(x):
        v=str(x)
        safe = {'paid','unpaid','processing','finalized','failed','complete',
                'verify','callback','redirect','redirecttopaymentpage',
                'successful','success','requested','pending','returned',
                'received','reported_unknown','success_reported',
                'requested_or_processed'}
        return v if v.casefold() in safe or re.fullmatch(r'[A-Z]{1,3}[0-9]{4,6}',v) else '[other_status_redacted]'
    return {
        'request_id':request_id,
        'status':journey['status'],
        'elapsed_ms':duration,
        'version':journey['version'],
        'step_count':len(journey['steps']),
        'behavior_kind':journey.get('behavior_kind'),
        'identity_status':journey.get('identity_status'),
        'canonical_occurrence_key':journey.get('canonical_occurrence_key'),
        'provisional_reference':journey.get('provisional_reference'),
        'resolved_occurrences':[dict(occurrence_key=x['occurrence_key'],
            anchor_request_key=x['anchor_request_key'],kind=x['kind'],
            family_id=x['family_id']) for x in journey.get('resolved_occurrences',[])],
        'observed_service_execution_count':journey.get('observed_service_execution_count'),
        'observed_product_reservation_execution_count':journey.get('observed_product_reservation_execution_count'),
        'observed_wallet_funding_execution_count':journey.get('observed_wallet_funding_execution_count'),
        'service_execution_count_scope':journey.get('service_execution_count_scope'),
        'confirmed_manual_action_count':journey.get('confirmed_manual_action_count'),
        'bridge_diagnostics':[dict(name=x['name'],status=x['status'],scope=x['scope'],
            precision=x.get('precision'),
            indexed_kinds=x.get('indexed_kinds',[]),
            missing_indexed_kinds=x.get('missing_indexed_kinds',[]),
            raw_stage=x['raw_stage'],parsed_stage=x['parsed_stage'],indexed_stage=x['indexed_stage'],
            edge_stage=x['edge_stage'],reachable_stage=x['reachable_stage'],
            evidence_refs=[dict(origin_key=e['origin_key'],version_key=e['version_key'],
                                field_path=e['field_path'],kind=e.get('kind')) for e in x['evidence_refs']])
           for x in journey.get('bridge_diagnostics',[])],
        'rejected_binding_count':len(journey.get('rejected_bindings',[])),
        'behavior_evidence':journey.get('behavior_evidence'),
        'edge_count':len(journey['edges']),
        'roles':[dict(api=s['api'].split(' Line:')[0],role=s['role'],
                      initiation=s['initiation'],anchor=s['anchor']) for s in journey['steps']],
        'observed_statuses':[dict(axis=o['axis'],value=masked_status(o['value']),
                    source_api=o['callpath'].split(' Line:')[0],
                    tehran_time=o['tehran_time'])
            for o in journey['timeline'] if o['axis'] in safe_axes][:70],
        'truncated':journey['truncated'],
        'truncation_reasons':journey['truncation_reasons'],
        'coverage_caveats':journey.get('coverage_caveats',[]),
        'fulfillment_statuses_observed':[masked_status(x) for x in journey.get('fulfillment_statuses_observed',[])],
        'fulfillment_history_complete':journey.get('fulfillment_history_complete',False),
        'limitations':journey['limitations'],
        'customer_action_count':journey['customer_action_count'],
        'financial_confirmation':journey['financial_confirmation'],
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--request-id',action='append',default=[])
    args=parser.parse_args()
    try:
        opts=config_options(args.config)
        with ViewerDB(**opts) as db:
            result=[summarize(db,r) for r in (args.request_id or SAMPLES)]
        print(json.dumps({'diagnostics':result,'read_only':True},ensure_ascii=False,indent=2))
    except (ValueError, OSError) as exc:
        # Configuration/DB exceptions can contain secrets: never render DSN.
        print('Diagnostic failed: verify the isolated Viewer config and database state.',file=sys.stderr)
        raise SystemExit(2) from None

if __name__=='__main__':
    main()
