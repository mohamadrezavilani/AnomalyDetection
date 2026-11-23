"""Exact indexed behavior search and source-spelled identifiers for operators."""
from datetime import datetime, timedelta
import json
import re
from zoneinfo import ZoneInfo
from compact_behavior.extract import identity, behavior_id, instant
from compact_behavior.context import normalized_ip

ZONE = ZoneInfo('Asia/Tehran')
IP_INDEX = 'compact_context_ip_values'
IP_EXPRESSION = "jsonb_path_query_array(context, '$.values.ip[*].value'::jsonpath)"
FIELDS = ('request_id', 'session_id', 'ip', 'from', 'to')


def filters(args, stream):
    values = {key: args.get(key, '') for key in FIELDS}
    for key in ('ip','from','to'):values[key]=values[key].strip()
    clauses = []; params = []
    for key in ('request_id', 'session_id'):
        if values[key]:
            canonical = identity(values[key])
            if canonical is None:
                raise ValueError('شناسهٔ واردشده معتبر نیست.')
            if key == 'request_id':
                clauses.append('b.behavior_id=%s'); params.append(behavior_id(stream, canonical))
            else:
                clauses.append('b.session_id=%s'); params.append(canonical)
    if values['ip']:
        ip = normalized_ip(values['ip'])
        if ip is None:
            raise ValueError('IP معتبر وارد کنید.')
        values['ip'] = ip
        # A date-free IP search has an explicit visible 24-hour scope.
        if not values['from'] and not values['to']:
            now = datetime.now(ZONE).replace(microsecond=0)
            values['from'] = (now-timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S')
            values['to'] = now.strftime('%Y-%m-%dT%H:%M:%S')
        clauses.append("jsonb_path_query_array(c.context, '$.values.ip[*].value'::jsonpath) @> %s::jsonb")
        params.append(json.dumps([ip]))
    times = {}
    for key, op in (('from', '>='), ('to', '<')):
        if values[key]:
            if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d)?', values[key]):
                raise ValueError('تاریخ و ساعت میلادی را با زمان تهران وارد کنید.')
            try:
                local = datetime.fromisoformat(values[key]).replace(tzinfo=ZONE)
                times[key] = instant(local.isoformat(timespec='seconds'))
            except (ValueError, OverflowError):
                raise ValueError('تاریخ و ساعت معتبر نیست.') from None
            clauses.append('b.observed_at_ns'+op+'%s'); params.append(times[key])
    if len(times)==2 and times['from']>=times['to']:
        raise ValueError('زمان پایان باید بعد از زمان شروع باشد.')
    return values, ''.join(' AND '+c for c in clauses), params


def source_ids(state, canonical, name):
    values = state.get(name, []) or []
    return sorted({v for v in values if isinstance(v,str) and identity(v)==canonical})[:4]


def decorate(row, state):
    from .validation import REJECTIONS
    if row.get('validation_verified') or state.get('validation_verified'):
        row['validation_label'] = REJECTIONS[row['result_code']][1]
        row['quality'] = [q for q in row.get('quality', []) if q != 'unresolved_dispatch']

    row['rate_limited_attempt'] = row.get('api')=='Services.v1/InvoiceRegister' and row.get('result_code')=='GR0004'
    access = row.get('access_denied_attempt') or {}
    row['access_denied'] = (row.get('api') == 'Services.v1/InvoiceRegister' and row.get('result_code') == 'G00010' and access.get('verified') is True)
    attempt=(access if row['access_denied'] else row.get('rejected_attempt')) or {}
    row['requested_service']=attempt.get('service')
    if row['rate_limited_attempt'] and not row['requested_service']:
        from compact_behavior.services import operation_role
        actions={v['value'] for v in state.get('dispatch',[]) if v.get('kind')=='action'}
        if len(actions)==1 and operation_role(next(iter(actions))) in ('business','user_management'):
            row['requested_service']=next(iter(actions))
    row['original_request_ids'] = source_ids(state, row['request_id'], 'raw_request_ids')
    row['original_session_ids'] = source_ids(state, row.get('session_id'), 'raw_session_ids')
    return row


def originals(db, schema, rows):
    if not rows:return
    from .validation import candidate_sql, evidence_sql
    states = {r['behavior_id']: r for r in db.execute(
        f"SELECT b.behavior_id,CASE WHEN {candidate_sql()} THEN {evidence_sql()} ELSE false END AS validation_verified,state->'raw_request_ids' AS raw_request_ids,state->'raw_session_ids' AS raw_session_ids,state->'dispatch' AS dispatch FROM {schema}.behavior_payloads p JOIN {schema}.behaviors b USING(behavior_id) WHERE b.behavior_id=ANY(%s)",
        ([r['behavior_id'] for r in rows],)).fetchall()}
    for row in rows:decorate(row,states.get(row['behavior_id'],{}))


def index_state(db, schema):
    return db.execute('''SELECT i.indisvalid,i.indisready,pg_get_indexdef(i.indexrelid) AS definition,
        t.relname AS table_name,n.nspname AS table_schema
        FROM pg_index i JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace
        WHERE i.indexrelid=to_regclass(%s)''',(schema+'.'+IP_INDEX,)).fetchone()


def prepare_index(db, schema, *, progress=lambda stage: None):
    # Dedicated autocommit preparation connection, outside worker startup.
    if not re.fullmatch(r'p24_compact(?:_[a-z0-9_]{1,40})?',schema):
        raise ValueError('compact_schema_required')
    progress('CHECKING_INDEX')
    state = index_state(db,schema)
    if state:
        if (state['table_name']!='request_context' or state['table_schema']!=schema
                or 'USING gin' not in state['definition'] or 'jsonb_path_query_array' not in state['definition']
                or 'jsonb_path_ops' not in state['definition'] or '$."values"."ip"[*]."value"' not in state['definition']):
            raise ValueError('SEARCH_INDEX_NAME_OWNED_BY_DIFFERENT_DEFINITION')
        if state['indisvalid'] and state['indisready']:return 'ALREADY_READY'
        # An interrupted concurrent build may leave only this invalid index.
        progress('REMOVING_INVALID_INDEX')
        db.execute(f'DROP INDEX CONCURRENTLY {schema}.{IP_INDEX}')
    progress('BUILDING_INDEX_CONCURRENTLY')
    db.execute(f'CREATE INDEX CONCURRENTLY {IP_INDEX} ON {schema}.request_context USING gin (({IP_EXPRESSION}) jsonb_path_ops)')
    state = index_state(db,schema)
    if not state or not state['indisvalid'] or not state['indisready']:
        raise ValueError('SEARCH_INDEX_NOT_READY')
    return 'CREATED'


def scope_parts():
    expression = "(api=ANY(%s) OR (api=%s AND features->>'service_binding'=%s AND features->>'service_key'=ANY(%s)))"
    dispatch = "Services.v1/InvoiceRegister"
    binding = "SAME_REQUEST_REVIEWED_DISPATCH"
    attempt = "(api='Services.v1/InvoiceRegister' AND result_code='GR0004')"
    access_attempt = "(api='Services.v1/InvoiceRegister' AND result_code='G00010' AND features->'access_denied_attempt'->>'verified'='true')"
    return expression, dispatch, binding, attempt, access_attempt


def unknown_scope():
    from compact_behavior.services import operation_catalog, internal_proxies
    expression, dispatch, binding, attempt, access_attempt = scope_parts()
    # Preserve the installed build-30 partial index predicate. Later role
    # decisions are filtered only within that sparse population.
    known = sorted(api for api, row in operation_catalog()['routes'].items()
                   if row['role'] != 'unknown' and api != dispatch and api not in internal_proxies())
    return f'NOT COALESCE({expression} OR ({attempt} OR {access_attempt}),false)', [known, dispatch, binding, known]


def remaining_unknown_scope(schema):
    from .validation import verified_sql
    broad, args = unknown_scope()
    from compact_behavior.services import internal_proxies
    return (f'({broad}) AND NOT COALESCE(b.api=ANY(%s),false) AND NOT ({verified_sql(schema)})',
            [*args, sorted(internal_proxies())])
