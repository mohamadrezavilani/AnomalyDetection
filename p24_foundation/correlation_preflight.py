"""Read-only intake inspection for *uncontracted* future correlation markers.

This is deliberately NOT a P24_CORRELATION_V1 decoder.  No public envelope
schema or field-to-identifier mapping has been authenticated; treating a
marker as a typed identifier or a financial edge would produce false joins.
The original raw events remain the authority, untouched. This module reports
marker/field presence and provenance so a schema can be reviewed before a
future incremental ingestion rule is enabled.
"""
from __future__ import annotations

import gzip
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Iterable

MARKER = 'P24_CORRELATION_V1'
PREFLIGHT_VERSION = 'p24-correlation-preflight-LC1C'


def inspect_record(raw: object) -> list[dict]:
    """Recognize candidates without interpreting any identifier/relationship.

    A recognized marker means the *text* was seen, not that it is authoritative
    or that the envelope is correct. All candidates remain unsupported_schema.
    """
    if not isinstance(raw, dict):
        return []
    candidates = []
    message = raw.get('message')
    if isinstance(message, str) and MARKER in message:
        candidates.append(dict(path='message', source='text_marker',
                               announced_version=MARKER, status='unsupported_schema'))
    for key in ('correlation', 'Correlation'):
        if key not in raw:
            continue
        value = raw[key]
        announced = (value.get('version') or value.get('Version') or value.get('schema_version')) \
            if isinstance(value, dict) else None
        # A correlation field is only an envelope *candidate*. Field names and
        # nested namespace/scopes cannot be inferred from a C# model property.
        candidates.append(dict(path=key, source='structured_candidate',
                               announced_version=(announced if announced == MARKER else None),
                               status='unsupported_schema'))
    return candidates


def _source_locator(event: dict) -> str | None:
    index_id = event.get('_source_id')
    if isinstance(index_id, str) and index_id.strip():
        return index_id
    idx = event.get('_index')
    doc = event.get('_id')
    if isinstance(idx, str) and isinstance(doc, str) and idx and doc:
        return idx + ':' + doc
    return None


def _canonical_digest(event: dict) -> str:
    return hashlib.sha256(json.dumps(event, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':'), default=str).encode('utf-8')).hexdigest()


def scan_files(paths: Iterable[str | Path], *, max_records: int | None = None,
               sample_limit: int = 20) -> dict:
    """Inspect independently verified (or explicitly unverified) JSON windows.

    Each file is loaded individually to avoid materializing an entire corpus;
    this is an offline preflight, *not* a streaming ES collector or import.
    A configured record cap explicitly marks the coverage incomplete.
    """
    if max_records is not None and max_records <= 0:
        raise ValueError('max_records must be positive')
    if sample_limit < 0:
        raise ValueError('sample_limit must be non-negative')
    result = dict(version=PREFLIGHT_VERSION, mode='read_only_no_decode_no_join',
                  files=[], scanned_records=0, candidate_records=0,
                  candidate_fields=0, unsupported_schema=0,
                  duplicated_origin_captures=0, divergent_origin_captures_for_review=0,
                  missing_origin=0, samples=[], completed=True,
                  capture_comparison='serialized_export_variants_not_proven_source_conflicts',
                  schema_authority='not_provided', financial_finality='NOT_INFERRED')
    origins = {}
    for source in paths:
        path = Path(source)
        if not path.is_file() or not (path.name.endswith('.json.gz') or path.suffix == '.json'):
            raise ValueError(f'not a supported .json/.json.gz evidence file: {path}')
        with (gzip.open(path, 'rt', encoding='utf-8') if path.name.endswith('.gz')
              else path.open('r', encoding='utf-8')) as stream:
            content = json.load(stream)
        if isinstance(content, dict) and isinstance(content.get('logs'), list):
            events = content['logs']
            expected = content.get('count')
            snapshot_complete = content.get('complete')
        elif isinstance(content, list):
            events = content
            expected = None
            snapshot_complete = None
        else:
            raise ValueError(f'unsupported JSON root for {path.name}: expected logs array')
        file_result = dict(file=path.name, records_available=len(events),
                           records_scanned=0, candidate_records=0,
                           advertised_count=expected if isinstance(expected, int) else None,
                           advertised_complete=snapshot_complete if isinstance(snapshot_complete, bool) else None,
                           count_matches=(len(events) == expected if isinstance(expected, int) else None))
        result['files'].append(file_result)
        for row, event in enumerate(events):
            if max_records is not None and result['scanned_records'] >= max_records:
                result['completed'] = False
                break
            result['scanned_records'] += 1
            file_result['records_scanned'] += 1
            if not isinstance(event, dict):
                continue
            origin = _source_locator(event)
            if origin:
                digest = _canonical_digest(event)
                if origin in origins:
                    if origins[origin] == digest:
                        result['duplicated_origin_captures'] += 1
                    else:
                        result['divergent_origin_captures_for_review'] += 1
                else:
                    origins[origin] = digest
            else:
                result['missing_origin'] += 1
            candidates = inspect_record(event)
            if not candidates:
                continue
            result['candidate_records'] += 1
            file_result['candidate_records'] += 1
            result['candidate_fields'] += len(candidates)
            result['unsupported_schema'] += len(candidates)
            if len(result['samples']) < sample_limit:
                result['samples'].append(dict(file=path.name, row=row,
                                              source_origin=origin,
                                              candidate_fields=candidates))
        if not result['completed']:
            break
    return result
