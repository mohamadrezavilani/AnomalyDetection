"""Resolve only visible witness IDs, on demand, without changing detector records."""
from datetime import datetime
from zoneinfo import ZoneInfo
from psycopg.types.json import Jsonb
from compact_behavior import FIVE, inquiry, security
from . import search
from .search import source_ids


def bounds(result, start):
    return (result.get('period_start_ns') or start, result.get('period_end_ns') or start+FIVE)


def clock_input(ns):
    return datetime.fromtimestamp(ns // 10**9, ZoneInfo('Asia/Tehran')).strftime('%Y-%m-%dT%H:%M:%S')


def evidence(db, schema, stream, findings, *, per_finding):
    """One batch for identity, one for selected target scalars. No searches over IP or payloads."""
    ids = {}
    projections = {}
    for f in findings:
        witnesses = list(dict.fromkeys(f['result'].get('evidence', ())))[:per_finding]
        ids[f['finding_id']] = witnesses
        service, axis = f['service'], f['result'].get('numeric_path')
        field = dict(inquiry.ROUTES.get(service, ())).get(axis)
        if f['method'] not in ('repeated_target','target_diversity') or not field:
            continue
        providers = {path: dict(fields)[axis] for (s,path),fields in inquiry.PROVIDER_FIELDS.items()
                     if s == service and axis in dict(fields)}
        for bid in witnesses:
            projections[bid,service,axis] = dict(bid=bid,service=service,axis=axis,field=field,providers=providers)
    wanted = list({bid for group in ids.values() for bid in group})
    if not wanted:
        return {}
    records = db.execute(f"""SELECT b.behavior_id,b.request_id,b.api,b.observed_at_ns,b.result_code,b.session_id,
            b.features->>'service_key' AS service,p.state->'raw_request_ids' AS originals,
            c.context->'values'->'ip' AS ip_entries,c.context->'limited' AS limited,
            c.context->>'version' AS context_version
        FROM {schema}.behaviors b LEFT JOIN {schema}.behavior_payloads p USING(behavior_id)
        LEFT JOIN {schema}.request_context c USING(behavior_id)
        WHERE b.stream_id=%s AND b.behavior_id=ANY(%s)""",(stream,wanted)).fetchall()
    by_id = {r['behavior_id']:r for r in records}
    targets = {}
    if projections:
        # Project only the explicitly reviewed axis, including its provider-specific spelling.
        rows = db.execute(f"""SELECT x.bid,x.service,x.axis,b.features->%s::text->>x.axis AS fingerprint,
                b.features->>'input_asof_ns' AS asof,
                v.value AS value FROM jsonb_to_recordset(%s) x(bid text,service text,axis text,field text,providers jsonb)
            JOIN {schema}.behaviors b ON b.behavior_id=x.bid AND b.stream_id=%s
            JOIN {schema}.behavior_payloads p ON p.behavior_id=x.bid
            CROSS JOIN LATERAL jsonb_array_elements(p.state->'inputs') e
            CROSS JOIN LATERAL (SELECT CASE WHEN jsonb_typeof(e->'value')='array'
              THEN CASE WHEN jsonb_array_length(e->'value')=1 THEN e->'value'->0 END ELSE e->'value' END obj,
              CASE WHEN b.features->>'input_basis'='reviewed_same_request_provider' THEN x.providers->>(e->>'path')
              WHEN e->>'basis'='business_parameters' AND b.features->>'input_basis'='business_parameters' THEN x.field
              WHEN e->>'basis'='public_api' AND b.features->>'input_basis'='public_api'
                    AND e->>'path'=x.service AND b.api=x.service THEN x.field END name) chosen
            CROSS JOIN LATERAL (VALUES (obj->name),(obj->'Parameters'->name)) v(value)
            WHERE b.features->>'service_key'=x.service AND b.features->'input_feature_eligibility'->>'targets'='true'
              AND jsonb_typeof(v.value) IN ('number','string') AND length(v.value::text)<=1026""",
            (inquiry.POLICY,Jsonb(list(projections.values())),stream)).fetchall()
        for r in rows:
            if r['asof'] and inquiry.token(r['value']) == r['fingerprint']:
                targets[r['bid'],r['service'],r['axis']] = (r['value'],int(r['asof']))
    output = {}
    for f in findings:
        result = f['result']
        start,end = bounds(result,f['start_ns'])
        data = dict(rows=[], ips=[], targets=[], window={'from':clock_input(start),'to':clock_input(((end+10**9-1)//10**9)*10**9)})
        network = f['method']=='invalid_session_attempts'
        for bid in ids[f['finding_id']]:
            row = by_id.get(bid)
            if not row:
                continue
            raw = source_ids({'ids':row['originals']},row['request_id'],'ids')
            ip_entries = row['ip_entries'] or []
            if network:
                ctx = dict(version=row['context_version'],values={'ip':ip_entries},limited=row['limited'] or [])
                if result.get('entity_key') and security.network(ctx,end-1) == result['entity_key'] and len(ip_entries)==1:
                    if ip_entries[0]['value'] not in data['ips']:
                        data['ips'].append(ip_entries[0]['value'])
            else:
                for ip in ip_entries:
                    if ip.get('value') and ip['value'] not in data['ips']:
                        data['ips'].append(ip['value'])
            target = targets.get((bid,f['service'],result.get('numeric_path')))
            value = None
            if (target and target[1]<end and row['session_id']==f['session_id']
                    and row['observed_at_ns'] is not None and start<=row['observed_at_ns']<end):
                value = target[0]
                if value not in data['targets']:
                    data['targets'].append(value)
            data['rows'].append(dict(bid=bid,request_id=raw[0] if raw else row['request_id'],
                                     api=row['api'],service=row['service'],at=row['observed_at_ns'],
                                     code=row['result_code'],target=value))
        output[f['finding_id']] = data
    return output


def nearby(db, schema, stream, ip, window):
    """Short, explicitly requested context for a verified network finding."""
    from psycopg.errors import QueryCanceled
    try:
        with db.transaction():
            index = search.index_state(db,schema)
            if not index or not index['indisvalid'] or not index['indisready']:
                return None
            _, clause, args = search.filters(dict(ip=ip, **window),stream)
            rows=db.execute(f"""SELECT b.behavior_id,b.request_id,b.api,b.observed_at_ns,b.result_code,
                    p.state->'raw_request_ids' AS originals
                FROM {schema}.behaviors b JOIN {schema}.request_context c USING(behavior_id)
                LEFT JOIN {schema}.behavior_payloads p USING(behavior_id)
                WHERE b.stream_id=%s {clause} ORDER BY b.observed_at_ns DESC,b.behavior_id DESC LIMIT 12""",
                (stream,*args)).fetchall()
    except QueryCanceled:
        return None
    for row in rows:
        originals=source_ids({'ids':row.pop('originals')},row['request_id'],'ids')
        if originals:row['request_id']=originals[0]
    return rows
