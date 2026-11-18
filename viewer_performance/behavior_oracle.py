"""Complete retained-behavior and preservation reconciliation; correctness only.

Streams ordered rows through a server cursor; no all-history client fetch.
Execution timestamps are excluded only where they are not evidence. Financial
archives and all owned AD tables must stay byte-equivalent in behavior mode.
"""
import hashlib
import json
import uuid
from viewer_performance.capacity.oracle import PROJECTIONS


RETAINED={
    'viewer_events':'*','viewer_raw_events':'*','viewer_event_captures':'*','viewer_capture_projections':'*',
    'viewer_files':'file_hash,filename,window_start,window_end,declared_count,record_count,new_events,duplicate_events,conflicting_events,source_claim,issue',
    'viewer_requests':'*',
    'viewer_actions':'action_key,session_key,label,name,category,initiation,at_ns,current_outcome,root_request_key',
    'viewer_semantic_occurrences':PROJECTIONS['viewer_semantic_occurrences'],
    'viewer_semantic_transitions':PROJECTIONS['viewer_semantic_transitions'],
    'viewer_semantic_session_heads':'*','viewer_service_roles':PROJECTIONS['viewer_service_roles'],'viewer_service_role_history':'*',
}
ARCHIVE={
    'viewer_action_history':'TRUE','viewer_contract_identifiers':'TRUE','viewer_contract_edges':'TRUE',
    'viewer_links':"link_domain NOT IN ('access_session','query_parameters_hash')",
    'viewer_contract_observations':"axis NOT LIKE 'service_dispatch.%'",
    'viewer_service_roles':"reviewed=1 OR source='operator'",
}
SHARED={
    'viewer_links':"link_domain IN ('access_session','query_parameters_hash')",
    'viewer_contract_observations':"axis LIKE 'service_dispatch.%'",
}


def table_digest(db,table,columns='*',where='TRUE',check=lambda:None):
    # All identifiers and predicates come from the fixed catalog above or the
    # server's own table catalog. Never interpolate operator input.
    from psycopg import sql
    schema,name=table.split('.',1) if '.' in table else ('public',table)
    relation=sql.Identifier(schema,name)
    description=db.conn.execute(sql.SQL('SELECT '+columns+' FROM {} LIMIT 0').format(relation)).description
    selected=[r.name for r in description]
    keys=db.conn.execute('''SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid
        AND a.attnum=ANY(i.indkey) WHERE i.indrelid=%s::regclass AND i.indisprimary ORDER BY array_position(i.indkey,a.attnum)''',
        (schema+'.'+name,)).fetchall()
    order=[r['attname'] for r in keys if r['attname'] in selected] or selected
    # Complete selected-row ordering also covers intentionally projected PKs.
    order+= [n for n in selected if n not in order] if len(order)<len(keys) else []
    query=sql.SQL('SELECT '+columns+' FROM {} WHERE '+where+' ORDER BY {}').format(relation,sql.SQL(',').join(map(sql.Identifier,order)))
    digest=hashlib.sha256();count=0
    with db.conn.cursor(name='behavior_oracle_'+uuid.uuid4().hex[:12]) as cursor:
        cursor.execute(query)
        while True:
            check();rows=cursor.fetchmany(256)
            if not rows:break
            for row in rows:
                digest.update(json.dumps(dict(row),sort_keys=True,separators=(',',':'),default=lambda v:bytes(v).hex()).encode()+b'\n');count+=1
    return dict(rows=count,sha256=digest.hexdigest())


def retained(db,check=lambda:None):
    result={table:table_digest(db,table,columns,check=check) for table,columns in RETAINED.items()}
    result.update({table:table_digest(db,table,where=where,check=check) for table,where in SHARED.items()})
    if db.one("SELECT to_regclass('public.viewer_history_replay_state') AS name")['name']:
        result['viewer_history_replay_state']=table_digest(db,'viewer_history_replay_state',
            'id,run_id,from_ns,next_ns,end_ns,stream_key,keys_fingerprint,skipped_windows,published_windows,status,started_ns,ad_prepared,ad_started',check=check)
    return result


def archives(db,check=lambda:None):
    result={table:table_digest(db,table,where=where,check=check) for table,where in ARCHIVE.items()}
    # Viewer publication has no permission to change models or human feedback.
    tables=db.all("SELECT tablename FROM pg_tables WHERE schemaname='anomaly_detection' ORDER BY tablename")
    result.update({'anomaly_detection.'+r['tablename']:table_digest(db,'anomaly_detection.'+r['tablename'],check=check) for r in tables})
    return result
