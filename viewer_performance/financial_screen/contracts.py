"""Explicit lost coverage for the financial-product scope screen."""
MODES=('A','B1','B2','C','D')
FEATURES=('evidence','request_identity','typed_payment_graph','payment_outcomes',
    'canonical_executions','full_action_views','full_journey','general_models','financial_detectors')


def coverage(mode):
    if mode not in MODES:raise ValueError('unknown_financial_screen_mode')
    result={name:'NOT_EVALUATED' for name in FEATURES}
    result['evidence']='COMPLETE'
    if mode!='D':result['request_identity']='COMPLETE'
    if mode in ('A','C'):result['typed_payment_graph']='COMPLETE'
    if mode=='A':result['payment_outcomes']='COMPLETE';result['full_action_views']='COMPLETE'
    if mode in ('A','B1','C'):result['canonical_executions']='COMPLETE'
    if mode=='B2':result['canonical_executions']='PARTIAL_DEPENDENCY_SCOPE'
    # These experiments never run a web query-time journey or an AD model.
    # Existing absence of an authoritative money ledger remains explicit.
    return result


SCENARIOS=[
    dict(id='F1',name='Reuse of the same typed payment object across distinct actors/executions',
        required=['evidence','request_identity','typed_payment_graph','canonical_executions'],
        retained_in_C=True,decision='CANDIDATE_FOR_SELECTED_FINANCIAL_ADAPTER',
        limitation='A shared payment may be a legitimate basket or callback; not proof of fraud.'),
    dict(id='F2',name='Repeated or cross-actor use of invoice/query/bill identifiers',
        required=['evidence','request_identity','typed_payment_graph','canonical_executions'],
        retained_in_C=True,decision='CANDIDATE_FOR_SELECTED_FINANCIAL_ADAPTER',
        limitation='Typed issuer/scope and logical execution identity must be retained; retries are not independent fraud.'),
    dict(id='F3',name='Unusual volume or enumeration of financial-service subjects',
        required=['evidence','request_identity','canonical_executions'],
        retained_in_C=True,decision='REFERENCE_AND_SELECTED_DETECTOR_STILL_REQUIRED',
        limitation='Retained facts do not implement a calibrated detector or prove enough reference history.'),
    dict(id='F4',name='Logged payment completion versus per-bill service/result mismatch',
        required=['evidence','request_identity','typed_payment_graph','payment_outcomes'],
        retained_in_C=False,decision='DEFERRED_UNTIL_ITEM_OUTCOME_ADAPTER',
        limitation='C defers the materialized outcome; raw evidence and typed relations remain replayable.'),
    dict(id='F5',name='Confirmed debit/settlement, duplicate charge, refund or withdrawal reconciliation',
        required=['evidence','typed_payment_graph','authoritative_money_ledger'],
        retained_in_C=False,decision='BLOCKED_EXTERNAL_DEPENDENCY',
        limitation='The current log contract does not establish bank/core-ledger financial finality.'),
    dict(id='F6',name='General behavioral sequence/mix/content and complete user journey',
        required=['full_journey','general_models'],retained_in_C=False,decision='PROPOSE_DEFER',
        limitation='Broad or sequence-based abuse outside selected financial scenarios may be missed.'),
]


def consumer_gate(contract,feature):
    if contract.get(feature)!='COMPLETE':raise ValueError('OUTPUT_NOT_EVALUATED:'+feature)
