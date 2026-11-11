"""Safe diagnostics for an unpublished Viewer window; no raw exception text.

An exception raised with ``from None`` still retains __context__. Inspect that
chain so HTTP/network/SQL causes survive the live worker's safe public wrapper.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import socket
import ssl
from urllib.error import HTTPError, URLError

SAFE_CODES=frozenset('''capture_proof_incomplete capture_bounds_or_count_invalid
capture_identity_or_event_invalid capture_non_object_row capture_ingest_rejected
capture_changed_during_publication affected_dependency_budget_exceeded
capture_budget_expired invalid_search_page incomplete_search_page invalid_search_hits
inexact_search_total invalid_search_total search_total_changed invalid_search_hit
missing_stable_search_identity duplicate_search_origin search_event_outside_window
search_count_exceeded search_cursor_missing search_count_mismatch
existing_capture_hash_mismatch live_stream_not_initialized live_keys_changed
noncontiguous_forward_window recheck_unpublished_window
manual_recheck_cannot_skip_forward_gap viewer_worker_already_running
live_stream_or_keys_changed existing_viewer_keys_or_raw_identity_mismatch
invalid_closed_window window_not_closed requested_read_model_anchor_missing
set_private_elasticsearch_host set_private_elasticsearch_index invalid_es_request_timeout
invalid_es_page_size invalid_capture_budget pit_id_missing pit_id_invalid
pit_sort_cursor_invalid invalid_source_catalog_role source_catalog_evidence_missing
invalid_recent_window_count invalid_recent_start_time storage_digest_definition_mismatch
storage_index_definition_mismatch storage_primary_key_definition_mismatch
storage_requires_deterministic_collation invalid_storage_layout'''.split())
OWN_FILES=frozenset(('viewer_elastic.py','viewer_online.py','viewer_data.py',
    'viewer_contract.py','viewer_semantic_index.py','run_viewer_pilot.py','viewer_service_sync.py','viewer_service_catalog.py',
    'viewer_storage_keys.py','viewer_projection_writes.py'))


def _chain(error):
    result=[];seen=set()
    while isinstance(error,BaseException) and id(error) not in seen and len(result)<10:
        seen.add(id(error));result.append(error)
        reason=getattr(error,'reason',None)
        error=error.__cause__ or error.__context__ or (reason if isinstance(reason,BaseException) else None)
    return result


def describe_failure(error,*,stage='worker_step'):
    chain=_chain(error)
    detail=dict(stage=stage,code='unexpected_error',exception_type=type(error).__name__,
                exception_chain=[type(e).__name__ for e in chain])
    locations=[]
    for e in reversed(chain):
        tb=e.__traceback__
        while tb:
            name=Path(tb.tb_frame.f_code.co_filename).name
            if name in OWN_FILES:
                locations.append(dict(file=name,function=tb.tb_frame.f_code.co_name,line=tb.tb_lineno))
            tb=tb.tb_next
    if locations:detail['locations']=locations[-8:]
    if any(x['file']=='viewer_elastic.py' for x in locations):detail['stage']='elasticsearch_capture'
    elif any(x['file'] in ('viewer_service_sync.py','viewer_service_catalog.py') for x in locations):detail['stage']='service_catalog_sync'
    elif any(x['function']=='publish_capture' for x in locations):detail['stage']='publication'
    for e in reversed(chain):
        if isinstance(e,HTTPError):
            detail.update(code={400:'es_request_rejected',401:'es_authentication_failed',
                403:'es_permission_denied',404:'es_index_or_endpoint_not_found',
                429:'es_rate_limited',502:'es_gateway_error',503:'es_unavailable',
                504:'es_gateway_timeout'}.get(e.code,'es_http_error'),http_status=e.code)
            # Extract only a machine error type, never the reason, URL, body,
            # credentials, returned hits, request IDs or SQL parameter values.
            try:
                payload=json.loads(e.read(65536))
                kind=payload.get('error',{}).get('type')
                if isinstance(kind,str) and re.fullmatch(r'[a-z][a-z0-9_]{0,79}',kind):
                    detail['elasticsearch_error_type']=kind
            except Exception:pass
            return detail
        sqlstate=getattr(e,'sqlstate',None)
        if isinstance(sqlstate,str) and re.fullmatch(r'[A-Z0-9]{5}',sqlstate):
            detail.update(code='postgresql_error',sqlstate=sqlstate,exception_type=type(e).__name__)
            return detail
        if isinstance(e,ssl.SSLCertVerificationError):
            detail['code']='tls_certificate_verification_failed';return detail
        if isinstance(e,socket.gaierror):
            detail['code']='dns_resolution_failed';return detail
        if isinstance(e,(TimeoutError,socket.timeout)):
            detail['code']='connection_or_capture_timeout';return detail
        if isinstance(e,ConnectionRefusedError):
            detail['code']='connection_refused';return detail
        if isinstance(e,FileNotFoundError):
            detail['code']='local_file_missing';return detail
        if isinstance(e,PermissionError):
            detail['code']='local_file_permission_denied';return detail
        if isinstance(e,json.JSONDecodeError):
            detail['code']='invalid_json_response_or_capture';return detail
        if isinstance(e,ValueError) and str(e) in SAFE_CODES:
            detail['code']=str(e);return detail
        if isinstance(e,URLError):
            detail['code']='network_request_failed';return detail
        if isinstance(e,OSError):
            detail['code']='io_or_network_error'
            for key in ('errno','winerror'):
                value=getattr(e,key,None)
                if type(value) is int:detail[key]=value
            return detail
    return detail
