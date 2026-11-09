"""LC3A evidence-aware guard audit for the original R5 86-case acceptance matrix.

Running synthetic unit guards is not end-to-end scenario acceptance. Every full
acceptance status intentionally remains NOT_EXECUTED until source-specific,
contract, isolated PostgreSQL and/or actual rollout evidence is reviewed.
Never reads operational databases; never changes Viewer state.
"""
from __future__ import annotations
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import platform
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
MATRIX = ROOT / 'validation' / 'R5_ACCEPTANCE_MATRIX_86.csv'

# Only map tested invariants to the original R5 case they partially protect.
# Mapping here NEVER changes reviewer_executed_result/acceptance status.
GUARDS = {
    'P05': 'tests.test_viewer_contract_r5.R5ContractTests.test_two_tokens_not_superseded_and_sessionless_webhook',
    'P07': 'tests.test_viewer_contract_r5.R5ContractTests.test_same_platform_object_separate_executions',
    'P08': 'tests.test_viewer_contract_r5.R5ContractTests.test_two_tokens_not_superseded_and_sessionless_webhook',
    'P09': 'tests.test_viewer_lc2_session_behavior.LC2SessionBehaviorTests.test_product_reservation_in_payment_request_counts_once',
    'P11': 'tests.test_viewer_r6_service_journey.R6JourneyTest.test_topup_separate_invoice_funds_and_fulfillment_report',
    'N01': 'tests.test_viewer_r6_service_journey.R6JourneyTest.test_basket_and_same_session_do_not_join_different_attempts',
    'N05': 'tests.test_viewer_lc1_anchor_resolver.LC1AnchorResolverTests.test_explicit_eligible_provider_binding_only',
    'N08': 'tests.test_viewer_contract_r5.R5ContractTests.test_multiple_bills_dont_cross_product_and_unsupported_status_not_success',
    'N09': 'tests.test_viewer_contract_r5.R5ContractTests.test_multiple_bills_dont_cross_product_and_unsupported_status_not_success',
    'N13': 'tests.test_viewer_contract_r5.R5ServiceBoundaryTests.test_nested_status_not_replaced_by_transport_success',
    'N16': 'tests.test_viewer_r6_service_journey.R6JourneyTest.test_wallet_funding_does_not_join_create_by_time_or_session',
    'N17': 'tests.test_viewer_contract_r5.R5ContractTests.test_opaque_case_and_bill_pairs_and_no_fuzzy_ids',
    'N21': 'tests.test_viewer_contract_r5.R5ServiceBoundaryTests.test_provider_purchase_webhook_report_separate_from_financial',
    'N24': 'tests.test_viewer_lc2_session_behavior.LC2SessionBehaviorTests.test_range_does_not_prove_absence_and_bad_cursors_are_rejected',
    'N27': 'tests.test_viewer_lc2c_coverage.LC2CCoverageTests.test_multiple_client_roots_remain_ambiguous_not_two_actions',
    'N28': 'tests.test_viewer_contract_r5.R5CaptureTests.test_replay_compatible_capture_preserves_raw_and_does_not_conflict',
    'N29': 'tests.test_viewer_lc2_session_behavior.LC2SessionBehaviorTests.test_two_five_minute_windows_stitch_one_request_execution',
    'N32': 'tests.test_viewer_contract_r5.R5ContractTests.test_opaque_case_and_bill_pairs_and_no_fuzzy_ids',
    'R2-T16': 'tests.test_viewer_contract_r5.R5CaptureTests.test_timezone_precision_projection_vs_material_change',
    'R3-T01': 'tests.test_viewer_lc2_session_behavior.LC2SessionBehaviorTests.test_funding_independent_of_callback_ownership_by_time',
    'R3-T09': 'tests.test_viewer_lc2d_semantic_coverage.LC2DTechnicalClassificationTests.test_catalog_family_is_context_and_never_purchase_anchor',
    'R4-T02': 'tests.test_viewer_r6_service_journey.R6JourneyTest.test_topup_separate_invoice_funds_and_fulfillment_report',
    'R5-T03': 'tests.test_viewer_r6_service_journey.R6JourneyTest.test_topup_separate_invoice_funds_and_fulfillment_report',
    'R5-T06': 'tests.test_viewer_lc2_session_behavior.LC2SessionBehaviorTests.test_owner_confirmed_automatic_roots_never_counted_even_if_misclassified',
    'R5-T08': 'tests.test_viewer_contract_r5.R5CaptureTests.test_replay_compatible_capture_preserves_raw_and_does_not_conflict',
}

EXPECTED_CASES = 86


def sha_file(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(part)
    return h.hexdigest()


def read_matrix(path):
    with path.open(encoding='utf-8-sig', newline='') as stream:
        cases = list(csv.DictReader(stream))
    ids = [case['id'] for case in cases]
    if len(ids) != EXPECTED_CASES or len(set(ids)) != EXPECTED_CASES:
        raise ValueError(f'invalid_source_matrix_expected_{EXPECTED_CASES}_unique_cases_found_{len(ids)}')
    if set(GUARDS) - set(ids):
        raise ValueError('guard_case_not_found_in_original_matrix')
    return cases


def run_guards(names):
    """Execute named isolated tests; reject nonexistent and skipped guards."""
    loader = unittest.defaultTestLoader
    results = {}
    for name in sorted(names):
        suite = loader.loadTestsFromName(name)
        stream = io.StringIO()
        result = unittest.TextTestRunner(stream=stream, verbosity=1).run(suite)
        if result.testsRun != 1:
            status = 'invalid_test_mapping'
        elif result.errors or result.failures or result.unexpectedSuccesses:
            status = 'failed'
        elif result.skipped or result.expectedFailures:
            status = 'not_executed_skipped'
        elif result.wasSuccessful():
            status = 'passed_synthetic_guard_only'
        else:
            status = 'invalid_result'
        results[name] = {'status':status, 'tests_run':result.testsRun,
            'failures':len(result.failures), 'errors':len(result.errors),
            'skipped':len(result.skipped), 'output':stream.getvalue()[-1400:] if status != 'passed_synthetic_guard_only' else None}
    return results


def build_report(matrix_path, execute=True):
    cases = read_matrix(matrix_path)
    result_map = run_guards(set(GUARDS.values())) if execute else {}
    records = []
    for case in cases:
        test = GUARDS.get(case['id'])
        status = result_map[test]['status'] if execute and test else 'not_mapped_or_not_run'
        records.append({
            'case_id': case['id'],
            'kind': case['kind'],
            'title_fa': case['title_fa'],
            'implementation_stage':case['implementation_stage'],
            'work_package':case['work_package'],
            'original_reviewer_status':case['reviewer_executed_result'],
            'synthetic_guard_test':test,
            'synthetic_guard_status':status,
            'full_end_to_end_acceptance':'NOT_EXECUTED',
            'financial_or_source_contract_gate':case['production_positive_assertion_gate'],
            'required_contract_assumptions':case['required_contract_assumptions'],
            'remaining_evidence_requirement':case['pass_evidence_required'],
            'fixture_reference_in_original_matrix':case['fixture_ref'],
            'original_expected_json':json.loads(case['expected_json']),
            'full_acceptance_missing_gate':'original_expected_assertion_and_isolated_postgresql_and_real_source_or_contract_evidence',
        })
    passed=sum(c['synthetic_guard_status']=='passed_synthetic_guard_only' for c in records)
    failures=[x for x in records if x['synthetic_guard_status'] not in ('passed_synthetic_guard_only','not_mapped_or_not_run')]
    unique_names=sorted(set(GUARDS.values()))
    used_files={}
    for name in unique_names:
        module='.'.join(name.split('.')[:-2])
        file=ROOT.joinpath(*module.split('.')).with_suffix('.py')
        if not file.is_file():
            raise ValueError('mapped_test_file_missing:'+str(file))
        used_files[str(file.relative_to(ROOT))]=sha_file(file)
    return {
        'version':'p24-lc3a-r5-acceptance-guard-audit-v1',
        'generated_utc':datetime.now(timezone.utc).isoformat(),
        'scope':'synthetic_regression_guards_only_not_full_end_to_end_acceptance',
        'read_only':True,
        'matrix_source':str(matrix_path.name),
        'matrix_sha256':sha_file(matrix_path),
        'python_version':platform.python_version(),
        'platform':platform.platform(),
        'counts':{
            'original_cases':len(cases),
            'guard_mapped_cases':len(GUARDS),
            'unique_guard_tests':len(unique_names),
            'synthetic_guard_passed_cases':passed,
            'synthetic_guard_unmapped_cases':len(cases)-len(GUARDS),
            'synthetic_guard_error_cases':len(failures),
            'fully_accepted_end_to_end_cases':0,
            'full_acceptance_not_executed_cases':len(cases),
        },
        'test_source_hashes':used_files,
        'guard_executions':result_map,
        'cases':records,
        'caveats':[
            'A synthetic guard can validate only a particular invariant, not the full expected_json contract.',
            'NOT_EXECUTED does not mean a scenario failed.',
            'An existing PASS from local unit testing cannot establish isolated PostgreSQL/real-Evidence acceptance.',
            'Authoritative financial settlement and owner attribution are not inferred.',
            'No operational database, Elasticsearch or Core access is performed by this command.',
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only R5/LC3 guard audit (not 86-case acceptance).')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--matrix', type=Path, default=MATRIX)
    parser.add_argument('--report-only', action='store_true', help='Do not execute any tests; all guards remain not run')
    args=parser.parse_args(argv)
    try:
        report = build_report(args.matrix, not args.report_only)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({'output':str(args.out),'counts':report['counts'],'read_only':True},ensure_ascii=False))
        return 1 if report['counts']['synthetic_guard_error_cases'] else 0
    except Exception as exc:
        print(f'LC3A_ACCEPTANCE_AUDIT_FAILED: {type(exc).__name__}: {exc}',file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
