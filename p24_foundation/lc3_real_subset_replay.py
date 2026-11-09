"""LC3E: bounded replay of *real* indexed event bodies in isolated SQLite.

Source is a guarded, read-only PostgreSQL/SQLite Viewer. Original raw bodies are
held only in process and deleted temporary files; output has no PII. Replays
prove only the selected complete RequestIDs' evidence and request-level
projection, never whole-ES completeness, human clicks or money movement.
"""
from __future__ import annotations
from collections import defaultdict
import gzip
import hashlib
import json
import random
import tempfile
import zlib
from pathlib import Path

from .viewer_data import ViewerDB, source_identity
from .lc3_readmodel_audit import BUCKET_NS

VERSION = 'p24-lc3e-real-source-bounded-replay-v1'
MAX_REQUESTS = 4
MAX_REQUEST_EVENTS = 250
MAX_SELECTION_CANDIDATES = 40


def _rows(db, sql, args=()):
    return db.all(sql, args)


def _canonical_rows(db, requests):
    """Comparable columns only. Do not include file name or arrival order."""
    result = {}
    fields = {
        'viewer_requests': 'request_key,session_key,identity_state,started_ns,ended_ns,root_ns,root_call,root_code,root_count,event_count,sql_count,provider_count,conflicted,initiation',
        'viewer_events': 'origin_key,version_key,request_key,at_ns,callpath,kind,code,observation',
        'viewer_contract_identifiers': 'origin_key,version_key,request_key,issuer,kind,scope,field_path,identity_key',
        'viewer_contract_observations': 'origin_key,version_key,request_key,at_ns,callpath,axis,value,field_path,authority',
        'viewer_contract_edges': 'edge_key,relation_type,from_typed_id,to_typed_id,scope,evidence_origin,evidence_version,evidence_path,request_key,eligibility,rule_version,confidence,observed_ns',
    }
    for table, cols in fields.items():
        values = []
        for req in requests:
            values.extend(_rows(db, f'SELECT {cols} FROM {table} WHERE request_key=?', (req,)))
        # SQLite and PG can disagree on row ordering; normalize them.
        result[table] = sorted(values, key=lambda r: json.dumps(r, sort_keys=True, default=str))
    return result


def _digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(',', ':'), default=str).encode()).hexdigest()


def _candidate_keys(source):
    query = '''SELECT r.request_key FROM viewer_requests r
      WHERE r.conflicted=0 AND r.event_count BETWEEN 2 AND ?
        AND r.started_ns IS NOT NULL AND r.ended_ns IS NOT NULL
        AND r.started_ns / ? <> r.ended_ns / ?
        AND substr(r.root_call,1,10)='Services.v'
      ORDER BY r.request_key LIMIT ?'''
    return [r['request_key'] for r in _rows(source, query,
        (MAX_REQUEST_EVENTS, BUCKET_NS, BUCKET_NS, MAX_SELECTION_CANDIDATES))]


def _get_request_evidence(source, key, keys_path):
    query = '''SELECT e.origin_key,e.version_key,e.request_key,e.file_hash,e.row_number,
                      f.window_start,f.window_end,b.payload
        FROM viewer_events e JOIN viewer_raw_events b
             ON e.origin_key=b.origin_key AND e.version_key=b.version_key
        JOIN viewer_files f ON e.file_hash=f.file_hash
        WHERE e.request_key=? ORDER BY e.origin_key,e.version_key'''
    rows = _rows(source, query, (key,))
    if not 2 <= len(rows) <= MAX_REQUEST_EVENTS:
        return None, 'event_budget_or_missing_raw'
    # Same read-model semantics as original ingestion, including HMAC origin.
    # Use the keys file to verify unmodified identity, rather than invent a
    # synthetic source ID for records lacking Elasticsearch index+document ID.
    from .privacy import Keys
    from .viewer_data import token
    keys = Keys.read(keys_path)
    outputs = []
    for row in rows:
        try:
            record = json.loads(zlib.decompress(bytes(row['payload'])).decode('utf-8'))
        except (TypeError,ValueError,zlib.error,UnicodeError):
            return None, 'raw_decode_failed'
        idx, docid = source_identity(record)
        if not idx or not docid:
            return None, 'missing_stable_source_identity'
        if token(keys, 'origin', [idx,docid]) != row['origin_key'] or token(keys, 'version', record) != row['version_key']:
            return None, 'origin_or_version_mismatch'
        if token(keys, 'request', record.get('RequestID')) != key:
            # The source may have opaque/nontrivial request normalization: do
            # not fabricate equivalence or force a replay in that case.
            from .parser import opaque
            if token(keys, 'request', opaque(record.get('RequestID'))) != key:
                return None, 'request_identity_mismatch'
        outputs.append((row, record))
    if len({r['file_hash'] for r,_ in outputs}) < 2:
        return None, 'single_source_window_only'
    if len({(r['window_start'],r['window_end']) for r,_ in outputs}) < 2:
        return None, 'no_distinct_declared_windows'
    return outputs, None


def _write_subset_files(temp_dir, selected):
    grouped = defaultdict(list)
    provenance = {}
    for output in selected:
        for row, raw in output:
            grouped[row['file_hash']].append((row['row_number'],raw))
            window = (row['window_start'],row['window_end'])
            if row['file_hash'] in provenance and provenance[row['file_hash']] != window:
                raise ValueError('inconsistent_source_file_window')
            provenance[row['file_hash']] = window
    files=[]
    for n, file_hash in enumerate(sorted(grouped)):
        start,end = provenance[file_hash]
        recs = [v for _,v in sorted(grouped[file_hash], key=lambda pair: pair[0])]
        path=temp_dir / f'subset_{n:03d}.json.gz'
        # Deliberately NOT a verified/full Elasticsearch export. Source
        # membership will be different, while identities must match.
        with gzip.open(path,'wt',encoding='utf-8') as f:
            json.dump({'window_start':start,'window_end':end,'count':len(recs),
                       'logs':recs},f,ensure_ascii=False)
        files.append(path)
    return files


def _replay(files, selected_keys, keys_path, directory, order):
    path=directory/'scratch.sqlite'
    with ViewerDB(sqlite_path=path,keys_path=keys_path) as temp:
        temp.init()
        for f in order:
            ingest=temp.ingest([files[f]])
            if len(ingest)!=1 or ingest[0]['status']!='IMPORTED':
                raise ValueError('replay_import_rejected')
        temp.rebuild()
        temp.rebuild_payment_contract()
        snap=_canonical_rows(temp,selected_keys)
        # Reimport EXACT same subset files, verifying no additional evidence.
        before = _digest(snap)
        repeated = temp.ingest(files)
        if any(v['status']!='ALREADY_IMPORTED' for v in repeated):
            raise ValueError('repeat_ingestion_not_idempotent')
        after=_digest(_canonical_rows(temp,selected_keys))
        return snap, before == after


def replay_real_readmodel_subset(source, *, keys_path, sample_limit=2):
    if isinstance(sample_limit,bool) or not isinstance(sample_limit,int) or not 1<=sample_limit<=MAX_REQUESTS:
        raise ValueError('sample_limit_must_be_1_to_4')
    keys_path=Path(keys_path).expanduser().resolve()
    if not keys_path.is_file():raise ValueError('private_viewer_keys_missing')
    selected=[]; skip_counts=defaultdict(int); examined=0
    candidates=_candidate_keys(source)
    for key in candidates:
        examined += 1
        evidence, problem=_get_request_evidence(source,key,keys_path)
        if problem:skip_counts[problem]+=1;continue
        selected.append((key,evidence))
        if len(selected)>=sample_limit:break
    if not selected:
        return {'version':VERSION,'read_only_source':True,'isolated_replay':True,
            'status':'INSUFFICIENT_REPLAYABLE_SOURCE_EVIDENCE',
            'source_candidates_examined':examined,'replayable_requests':0,
            'skip_reasons':dict(skip_counts),'fully_accepted_end_to_end_cases':0,
            'limitations':['No event was rewritten or assigned a fabricated source ID.']}
    keys=[key for key,_ in selected]
    # Read source projections in one stable source transaction (PG REPEATABLE READ
    # is configured by caller). Capture once before replay, never mutate source.
    expected=_canonical_rows(source,keys)
    results=[]
    with tempfile.TemporaryDirectory(prefix='p24_lc3e_private_') as work:
        directory=Path(work)
        files=_write_subset_files(directory, [ev for _,ev in selected])
        orders=[('chronological',list(range(len(files)))),
                ('reverse',list(reversed(range(len(files)))))]
        shuffled=list(range(len(files)));random.Random(20261026).shuffle(shuffled)
        orders.append(('shuffled',shuffled))
        for name,ordered in orders:
            run_dir=directory / ('run_'+name)
            run_dir.mkdir()
            snapshot,idem=_replay(files,keys,keys_path,run_dir,ordered)
            results.append((name,snapshot,idem))
    digests=[_digest(snapshot) for _,snapshot,_ in results]
    source_hash=_digest(expected)
    comparison={table: all(r[1][table] == expected[table] for r in results)
                for table in expected}
    return {
        'version':VERSION,'data_source':'guarded_isolated_viewer_existing_raw_evidence',
        'read_only_source':True,'isolated_replay':True,'source_is_subset_not_complete_ES':True,
        'status':'COMPLETED','source_candidates_examined':examined,
        'replayable_requests':len(keys),'replayed_raw_events':sum(len(ev) for _,ev in selected),
        'original_declared_source_windows':len(files),'order_modes':[r[0] for r in results],
        'distinct_file_orders_tested':len({tuple(o) for _,o in orders}),
        'order_independent_derived_snapshot':len(set(digests))==1,
        'repeat_import_idempotent':all(r[2] for r in results),
        'matches_indexed_source_projection_by_table':comparison,
        'selected_request_projection_matches_source':comparison['viewer_requests'],
        'selected_evidence_projection_matches_source':all(comparison[k] for k in comparison if k!='viewer_requests'),
        'derived_projection_hash':digests[0], 'indexed_projection_hash':source_hash,
        'skipped_source_candidates_by_reason':dict(skip_counts),
        'fully_accepted_end_to_end_cases':0,
        'financial_confirmation':'unverified',
        'limitations':[
            'Selected complete RequestIDs only; related payment chains and full Session histories may be outside the subset.',
            'Original source file counts are NOT replayed; subset windows are not certified Elasticsearch exports.',
            'No independent late-arrival timestamp is established by replaying existing records.',
            'No bank capture, refund, confirmed user click or full R5 case acceptance is inferred.',
            'Operator-authored service role changes are not replicated to the temporary replay.',
        ],
    }
