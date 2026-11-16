"""Streaming canonical comparisons; no UI/Flask dependency or sampled hashes.

The evidence and projection contracts extend the existing qualification
digests with revision, full transition history and operator service roles.
Only execution timestamps are omitted. Event times and causal revisions stay.
"""
import hashlib
import json


EVIDENCE=('viewer_events','viewer_links','viewer_raw_events',
    'viewer_event_captures','viewer_capture_projections')
PROJECTIONS={
    'viewer_requests':'*','viewer_actions':'*','viewer_action_history':'*',
    'viewer_contract_identifiers':'*','viewer_contract_edges':'*','viewer_contract_observations':'*',
    'viewer_semantic_occurrences':'''request_key,anchor_key,session_key,anchor_ns,kind,
        occurrence_key,root_call,root_code,family_id,family_label_fa,category,initiation,state,revision''',
    'viewer_semantic_session_heads':'*',
    'viewer_semantic_transitions':'''request_key,revision,old_kind,new_kind,
        old_occurrence_key,new_occurrence_key,transition''',
    'viewer_service_roles':'service_path,role,initiation,source,reviewed,note',
}


def digest_table(db,table,columns):
    description=db.sql('SELECT '+columns+' FROM '+table+' LIMIT 0').description
    order=','.join(str(i) for i in range(1,len(description)+1))
    cursor=db.sql('SELECT '+columns+' FROM '+table+' ORDER BY '+order)
    count=0;digest=hashlib.sha256()
    while True:
        rows=cursor.fetchmany(500)
        if not rows:break
        for row in rows:
            encoded=json.dumps(dict(row),sort_keys=True,separators=(',',':'),ensure_ascii=True,
                default=lambda value:bytes(value).hex()).encode()
            digest.update(encoded+b'\n');count+=1
    return dict(rows=count,sha256=digest.hexdigest())


def evidence_digest(db):
    # Full row ordering is essential for capture rows sharing origin/version.
    return {table:digest_table(db,table,'*') for table in EVIDENCE}


def projection_digest(db):
    return {table:digest_table(db,table,columns) for table,columns in PROJECTIONS.items()}
