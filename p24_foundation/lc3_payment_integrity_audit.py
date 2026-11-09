"""LC3D read-only, source-scoped payment evidence audit of the isolated Viewer.

This intentionally reports typed-object cardinality, *request co-occurrence*
and evidence consistency. It never turns an invoice/K co-occurrence into a
confirmed financial allocation, bank capture, customer debit or human action.
No raw_value, unhashed token, IP, SessionID, payload or credentials are emitted.
"""
from __future__ import annotations

from time import monotonic

VERSION='p24-lc3d-payment-evidence-audit-v1'
MAX_SAMPLES=12


def _n(db, sql, args=()):
    row=db.one(sql,args)
    return int((row or {}).get('n') or 0)


def _inventory(db):
    identifiers=db.all('''SELECT kind, COUNT(*) AS occurrences, COUNT(DISTINCT identity_key) AS distinct_objects,
                          COUNT(DISTINCT request_key) AS distinct_request_contexts
                       FROM viewer_contract_identifiers GROUP BY kind ORDER BY kind''')
    relationships=db.all('''SELECT relation_type,eligibility,COUNT(*) AS evidence_edges,
                              COUNT(DISTINCT from_typed_id) AS distinct_sources,
                              COUNT(DISTINCT to_typed_id) AS distinct_targets
                       FROM viewer_contract_edges GROUP BY relation_type,eligibility
                       ORDER BY relation_type,eligibility''')
    statuses=db.all('''SELECT axis,authority,COUNT(*) AS evidence_rows,
                            COUNT(DISTINCT request_key) AS distinct_request_contexts
                     FROM viewer_contract_observations GROUP BY axis,authority
                     ORDER BY axis,authority''')
    return (
      [{k:(int(v) if k!='kind' else v) for k,v in r.items()} for r in identifiers],
      [{k:(int(v) if k in ('evidence_edges','distinct_sources','distinct_targets') else v)
        for k,v in r.items()} for r in relationships],
      [{k:(int(v) if k in ('evidence_rows','distinct_request_contexts') else v)
        for k,v in r.items()} for r in statuses],
    )


def _cardinality(db, limit):
    # Every invoice/payment pair here occurs in one request. This is *NOT* a
    # payment_for_exact_inquiry link or a debit count. Multiple candidate Ks
    # require retention, even when the invoice literal was the same.
    invoice_to_k = db.all('''SELECT i.identity_key AS invoice_identity,
                                COUNT(DISTINCT p.identity_key) AS coobserved_payment_objects,
                                COUNT(DISTINCT i.request_key) AS coobserved_request_contexts
                           FROM viewer_contract_identifiers i
                           JOIN viewer_contract_identifiers p ON p.request_key=i.request_key
                           WHERE i.kind='invoice' AND p.kind='internal_payment'
                           GROUP BY i.identity_key
                           HAVING COUNT(DISTINCT p.identity_key)>1
                           ORDER BY i.identity_key LIMIT ?''',(limit,)) if limit else []
    # Provider binding edges can be candidate-only: eligibility is explicitly
    # not equated with ownership or financial settlement.
    payment_to_provider = db.all('''SELECT from_typed_id AS internal_payment_reference,
                                     eligibility,COUNT(DISTINCT to_typed_id) AS provider_bindings,
                                     COUNT(*) AS evidence_edges
                              FROM viewer_contract_edges
                              WHERE relation_type IN ('provider_binding','candidate_provider_binding')
                              GROUP BY from_typed_id,eligibility
                              HAVING COUNT(DISTINCT to_typed_id)>1
                              ORDER BY from_typed_id,eligibility LIMIT ?''',(limit,)) if limit else []
    return {
        'multi_k_invoice_contexts_sampled':[
            {'invoice_typed_hash':r['invoice_identity'],
             'distinct_k_coobserved_in_requests':int(r['coobserved_payment_objects']),
             'distinct_request_contexts':int(r['coobserved_request_contexts']),
             'relationship_claim':'same_request_context_only_NOT_payment_allocation'} for r in invoice_to_k],
        'multi_provider_binding_samples':[
            {'internal_payment_typed_reference':r['internal_payment_reference'],
             'eligibility':r['eligibility'],
             'distinct_provider_bindings':int(r['provider_bindings']),
             'evidence_edges':int(r['evidence_edges']),
             'relationship_claim':'typed_binding_evidence_not_financial_finality'} for r in payment_to_provider],
        'samples_are_exhaustive':False,
    }


def _provenance(db):
    # All counted anomalies refer to *indexed evidence*. Queries do not use
    # volatile import times or unverified filename-based inferred identifiers.
    queries={
        'identifiers_missing_raw_event': '''SELECT COUNT(*) AS n FROM viewer_contract_identifiers c
          WHERE NOT EXISTS(SELECT 1 FROM viewer_events e
             WHERE e.origin_key=c.origin_key AND e.version_key=c.version_key)''',
        'observations_missing_raw_event': '''SELECT COUNT(*) AS n FROM viewer_contract_observations c
          WHERE NOT EXISTS(SELECT 1 FROM viewer_events e
             WHERE e.origin_key=c.origin_key AND e.version_key=c.version_key)''',
        'edges_missing_raw_event': '''SELECT COUNT(*) AS n FROM viewer_contract_edges c
          WHERE NOT EXISTS(SELECT 1 FROM viewer_events e
             WHERE e.origin_key=c.evidence_origin AND e.version_key=c.evidence_version)''',
        'edges_request_key_differs_from_raw_event': '''SELECT COUNT(*) AS n FROM viewer_contract_edges c
          JOIN viewer_events e ON e.origin_key=c.evidence_origin AND e.version_key=c.evidence_version
          WHERE c.request_key<>e.request_key''',
        'identifiers_request_key_differs_from_raw_event': '''SELECT COUNT(*) AS n FROM viewer_contract_identifiers c
          JOIN viewer_events e ON e.origin_key=c.origin_key AND e.version_key=c.version_key
          WHERE c.request_key<>e.request_key''',
        'observations_request_key_differs_from_raw_event': '''SELECT COUNT(*) AS n FROM viewer_contract_observations c
          JOIN viewer_events e ON e.origin_key=c.origin_key AND e.version_key=c.version_key
          WHERE c.request_key<>e.request_key''',
    }
    return {name:_n(db,sql) for name,sql in queries.items()}


def audit_payment_evidence(db,*, sample_limit=8):
    if isinstance(sample_limit,bool) or not isinstance(sample_limit,int) or not 0<=sample_limit<=MAX_SAMPLES:
        raise ValueError('sample_limit_must_be_between_0_and_12')
    start=monotonic()
    inventory,relationships,statuses=_inventory(db)
    examples=_cardinality(db,sample_limit)
    provenance=_provenance(db)
    warnings=[]
    if any(provenance.values()):warnings.append('indexed_evidence_provenance_inconsistency_requires_review')
    if any(r['eligibility']!='eligible' for r in relationships):
        warnings.append('candidate_or_reported_edges_are_not_proof_of_financial_allocation')
    return {
        'version':VERSION,
        'data_source':'isolated_viewer_read_model_only',
        'read_only':True,
        'inventory':{'identifier_kinds':inventory,'relation_evidence':relationships,
                     'independent_status_axes':statuses},
        'cardinality_witnesses':examples,
        'evidence_integrity':{'checks':provenance,
                              'all_checked_references_consistent':not any(provenance.values()),
                              'scope':'indexed_viewer_evidence_not_full_elasticsearch'},
        'observed_query_elapsed_ms':round((monotonic()-start)*1000,1),
        'assessment':{
            'payment_objects_and_attempts':'CARDINALITY_OBSERVED_NOT_FINANCIAL_CAPTURE',
            'historical_provider_token_bindings':'NO_OVERWRITE_PROVEN_BY_THIS_AUDIT',
            'full_R5_case_acceptance':'NOT_EXECUTED',
            'fully_accepted_end_to_end_cases':0,
            'observed_service_execution_count':None,
            'confirmed_manual_action_count':None,
            'financial_confirmation':'unverified',
        },
        'warnings':warnings,
        'limitations':[
            'Same-request invoice/K co-observation does NOT prove payment for an exact inquiry, transfer or settlement.',
            'Multiple provider bindings may represent separate attempts; eligible edges are not bank confirmation.',
            'Axes are counted separately; provider Paid, fulfillment Finalized and internal Complete never collapse into one financial status.',
            'No authoritative ledger/capture/refund event is inferred from these Viewer projections.',
            'This is a snapshot audit, not a replay of the user PostgreSQL database in alternate ingestion orders.',
            'No canonical human action count or complete 86-case R5 acceptance is established.',
        ],
    }
