"""LC3B independent, strictly read-only evidence inventory of the isolated Viewer DB.

An indexed request spanning distinct five-minute event buckets is NOT proof
of a late arrival, deterministic replay, or the source completeness of ES.
No bank settlement, human intent or missing future event can be inferred here.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from .service_journey import semantic_execution_kind, stable_behavior_occurrence_key

BUCKET_NS = 300 * 1_000_000_000
MAX_SAMPLES = 20
_HEX64 = re.compile(r"^[a-f0-9]{64}$")


def _scalar(db, query, values=()):
    return db.one(query, values) or {}


def _counts(db):
    # This is one sequential pass over the isolated read model; no joins
    # between independently sourced financial objects are attempted.
    q = """SELECT COUNT(*) AS indexed_requests,
       SUM(CASE WHEN conflicted <> 0 THEN 1 ELSE 0 END) AS conflicted_requests,
       SUM(CASE WHEN root_call IS NULL THEN 1 ELSE 0 END) AS missing_root_requests,
       SUM(CASE WHEN root_call IS NULL AND root_count > 1 THEN 1 ELSE 0 END) AS multi_root_requests,
       SUM(CASE WHEN session_key IS NOT NULL THEN 1 ELSE 0 END) AS session_assigned_requests,
       SUM(CASE WHEN started_ns IS NOT NULL AND ended_ns IS NOT NULL
                     AND started_ns / ? <> ended_ns / ? THEN 1 ELSE 0 END) AS five_minute_spanning_requests,
       SUM(CASE WHEN started_ns IS NOT NULL AND ended_ns IS NOT NULL
                     AND started_ns / ? <> ended_ns / ? AND substr(root_call,1,10) = 'Services.v'
                     AND conflicted = 0 THEN 1 ELSE 0 END) AS five_minute_spanning_service_requests
       FROM viewer_requests"""
    row = _scalar(db, q, (BUCKET_NS,BUCKET_NS,BUCKET_NS,BUCKET_NS))
    return {k:int(v or 0) for k,v in row.items()}


def _event_evidence(db, request_key):
    records=db.all("""SELECT origin_key,version_key,file_hash,at_ns,kind
                        FROM viewer_events WHERE request_key=?
                        ORDER BY at_ns,origin_key,version_key LIMIT 10001""", (request_key,))
    limited=len(records)>10000
    records=records[:10000]
    unique_origins={r['origin_key'] for r in records}
    revisions={}
    for row in records:
        revisions.setdefault(row['origin_key'],set()).add(row['version_key'])
    times=[int(r['at_ns']) for r in records if r['at_ns'] is not None]
    buckets=sorted({t//BUCKET_NS for t in times})
    # File membership alone does not establish distinct *window declarations*;
    # the import metadata is separately inspected, without exposing filenames.
    files=sorted({r['file_hash'] for r in records})
    declared=[]
    if files:
        placeholders=','.join('?' for _ in files)
        declared=db.all('SELECT file_hash,window_start,window_end,source_claim,issue '
                        'FROM viewer_files WHERE file_hash IN ('+placeholders+')', files)
    windows={(r['window_start'],r['window_end']) for r in declared
             if r['window_start'] and r['window_end']}
    return {
        'event_rows_sampled':len(records),
        'evidence_complete_for_request':not limited,
        'distinct_event_origins_sampled':len(unique_origins),
        'distinct_source_files_sampled':len(files),
        'distinct_declared_export_windows_sampled':len(windows),
        'source_claims_sampled':sorted({r['source_claim'] for r in declared}),
        'source_window_declarations_sampled':[{
            'window_start':r['window_start'],'window_end':r['window_end'],
            'source_claim':r['source_claim'],
            'import_issue_reported':bool(r['issue']),
        } for r in sorted(declared,key=lambda r:r['file_hash'])[:6]],
        'distinct_five_minute_time_buckets_sampled':len(buckets),
        'event_origin_revision_conflicts_sampled':sum(len(v)>1 for v in revisions.values()),
        'source_membership_hashes_sampled':files[:6],
        'origin_provenance_sampled': [
            {'origin_key':r['origin_key'], 'version_key':r['version_key']}
            for r in records[:3]
        ],
        'observed_event_span_utc': {
            'first':datetime.fromtimestamp(min(times)/1e9, timezone.utc).isoformat(),
            'last':datetime.fromtimestamp(max(times)/1e9, timezone.utc).isoformat(),
        } if times else None,
    }


def _sample(db, n):
    # The root filter targets independent observed services, not callbacks;
    # failure to find such a case is a limited coverage finding, not a failure.
    query="""SELECT r.request_key,r.root_call,r.identity_state,r.conflicted,r.event_count,
                r.started_ns,r.ended_ns,r.session_key,a.category,a.initiation
              FROM viewer_requests r LEFT JOIN viewer_actions a ON r.request_key=a.action_key
              WHERE r.started_ns IS NOT NULL AND r.ended_ns IS NOT NULL
                  AND r.started_ns / ? <> r.ended_ns / ?
                  AND r.conflicted=0 AND substr(r.root_call,1,10) = 'Services.v'
              ORDER BY r.request_key LIMIT ?"""
    rows=db.all(query, (BUCKET_NS,BUCKET_NS,n))
    results=[]
    for r in rows:
        if not _HEX64.fullmatch(r['request_key']):
            raise ValueError('unexpected_request_key_encoding')
        kind=semantic_execution_kind(r['root_call'],r['category'])
        evidence=_event_evidence(db,r['request_key'])
        results.append({
            # HMAC request key is retained only for lookup and cross-run witness
            # alignment; it is not an unhashed user/session identifier.
            'request_key':r['request_key'],
            'root_api':str(r['root_call']).split(' Line:',1)[0],
            'session_identity_present':bool(r['session_key']),
            'identity_state':r['identity_state'],
            'semantic_kind':kind,
            'occurrence_key':stable_behavior_occurrence_key(kind,r['root_call'],r['request_key']) if kind else None,
            'behavior_is_confirmed_manual':r['initiation']=='confirmed_manual',
            'observed_request_event_count':r['event_count'],
            'evidence':evidence,
            'cross_window_observation':(
                'different_declared_export_windows_and_time_buckets_observed'
                if evidence['distinct_declared_export_windows_sampled']>=2 and evidence['distinct_five_minute_time_buckets_sampled']>=2
                else 'event_time_span_observed_but_distinct_export_windows_unverified'),
            'full_r5_scenario_acceptance':'NOT_EXECUTED',
        })
    return results


def audit(db, *, sample_limit=5):
    if isinstance(sample_limit,bool) or not isinstance(sample_limit,int) or not 0<=sample_limit<=MAX_SAMPLES:
        raise ValueError('sample_limit_must_be_between_0_and_20')
    counts=_counts(db)
    samples=_sample(db,sample_limit) if sample_limit else []
    warnings=[]
    if counts.get('conflicted_requests'):
        warnings.append('conflicted_requests_require_separate_version_review')
    if len(samples)<sample_limit:
        warnings.append('fewer_cross_window_service_examples_in_index_than_requested')
    if any(s['evidence']['event_origin_revision_conflicts_sampled'] for s in samples):
        warnings.append('origin_revisions_present_do_not_select_latest_arbitrarily')
    return {
        'version':'p24-lc3b-isolated-readmodel-evidence-v1',
        'data_source':'isolated_viewer_read_model_only',
        'read_only':True,
        'counts':counts,
        'sample_limit':sample_limit,
        'sampled_cross_window_service_requests':samples,
        'witness_assessment':{
            'N28':{'status':'PARTIAL_INDEXED_EVIDENCE_ONLY',
                'what_is_checked':'request origin/version provenance and possible origin conflicts in bounded samples',
                'not_proven':'idempotent replay with identical derived graph and zero additional financial movement'},
            'N29':{'status':'PARTIAL_INDEXED_EVIDENCE_ONLY' if samples else 'NO_SAMPLE_IN_CAPTURE',
                'what_is_checked':'request identity across five-minute event time boundaries and source-file membership',
                'not_proven':'arrival-time lateness, order-independent full graph, payment history, revision recomputation'},
            'fully_accepted_end_to_end_cases':0,
            'full_r5_matrix_status':'UNCHANGED_LC3A_86_NOT_EXECUTED',
        },
        'warnings':warnings,
        'limitations':[
            'Five-minute event timestamp span is not proof of late Elasticsearch arrival.',
            'Source-file membership and claimed window ranges do not independently verify complete Elasticsearch exports.',
            'A source_claim of unverified_snapshot_claim is not verified provenance.',
            'The samples do not establish independent human clicks or confirmed financial settlement.',
            'Stable behavior keys are hashes of semantic request anchors, not final ownership evidence.',
            'Full R5 acceptance requires separate executable assertions, fixture hashes, isolated DB/UI witnesses and applicable contracts.',
        ],
    }
