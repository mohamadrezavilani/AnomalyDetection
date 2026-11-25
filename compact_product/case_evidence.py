"""Resolve only visible witness IDs, on demand, without changing detector records."""
from datetime import datetime
from zoneinfo import ZoneInfo
from collections import defaultdict
import logging
from psycopg.errors import QueryCanceled
from compact_behavior.extract import selected
from compact_behavior import FIVE, inquiry, security
from . import search
from .search import source_ids


def bounds(result, start):
    return (result.get('period_start_ns') or start, result.get('period_end_ns') or start+FIVE)


def clock_input(ns):
    return datetime.fromtimestamp(ns // 10**9, ZoneInfo('Asia/Tehran')).strftime('%Y-%m-%dT%H:%M:%S')


TARGET_METHODS = ('repeated_target', 'target_diversity', 'long_target_enumeration')


def verified_targets(row, axes):
    """Match original typed values to the projection consumed by the detector."""
    state = row.get('security_state')
    if not state:
        return {}
    # Use the same legacy-service repair as AD only when its SQL would fetch
    # retained state. Current witnesses already have the authoritative digest.
    features = row['features']
    if inquiry.POLICY not in features or features.get('service_binding') == 'UNRESOLVED_DISPATCH':
        features = next(security.legacy_rows([dict(row)]))['features']
    service = features.get('service_key')
    if (not features.get('input_feature_eligibility', {}).get('targets')
            or type(features.get('input_asof_ns')) is not int):
        return {}
    subjects = features.get(inquiry.POLICY) or {}
    entries, basis = selected(state, 'inputs', row['api'], service)
    found = {}
    for entry in entries:
        if basis == 'reviewed_same_request_provider':
            fields = inquiry.PROVIDER_FIELDS.get((service, entry['path']), ())
        elif basis == 'business_parameters' or (basis == 'public_api' and row['api'] == service):
            fields = inquiry.ROUTES.get(service, ())
        else:
            continue
        for axis, field in fields:
            if (service, axis) not in axes or not subjects.get(axis):
                continue
            values = [obj[field] for obj in inquiry.containers(entry.get('value')) if field in obj]
            if entry.get('representation') == 'FEATURES_ONLY_V1':
                saved = (entry.get('feature_snapshot') or {}).get('targets', {})
                values = [v.get('value') for name in (field, 'Parameters.'+field) for v in saved.get(name, ())]
            for value in values:
                if inquiry.token(value) == subjects[axis]:
                    found[service, axis] = (value, features['input_asof_ns'])
    return found


def evidence(db, schema, stream, findings, *, per_finding, selected_ids=None):
    try:
        with db.transaction():
            return load_evidence(db, schema, stream, findings, per_finding=per_finding, selected_ids=selected_ids)
    except QueryCanceled:
        logging.getLogger('compact_product.web').warning('web component=case_witnesses sqlstate=57014')
        return {f['finding_id']: dict(read_canceled=True) for f in findings}


def load_evidence(db, schema, stream, findings, *, per_finding, selected_ids):
    """Resolve only recorded witness IDs. Never search surrounding requests."""
    ids = {}
    projections = defaultdict(set)
    for f in findings:
        key = f['finding_id']
        witnesses = list(dict.fromkeys(f['result'].get('evidence') or ()))
        ids[key] = (selected_ids[key] if selected_ids is not None else witnesses[:per_finding])
        service, axis = f['service'], f['result'].get('numeric_path')
        if f['method'] in TARGET_METHODS and axis in dict(inquiry.ROUTES.get(service, ())):
            for bid in ids[key]:
                projections[bid].add((service, axis))
    wanted = list({bid for group in ids.values() for bid in group})
    if not wanted:
        return {}
    records = db.execute(f"""SELECT b.behavior_id,b.request_id,b.api,b.observed_at_ns,b.result_code,b.session_id,
            b.features->>'service_key' AS service,p.state->'raw_request_ids' AS originals,
            c.context->'values'->'ip' AS ip_entries,c.context->'limited' AS limited,
            c.context->>'version' AS context_version
        FROM {schema}.behaviors b JOIN {schema}.behavior_payloads p USING(behavior_id)
        LEFT JOIN {schema}.request_context c USING(behavior_id)
        WHERE b.stream_id=%s AND b.behavior_id=ANY(%s)""",(stream,wanted)).fetchall()
    by_id = {r['behavior_id']:r for r in records}
    targets = {}
    if projections:
        # Do not load all response payloads into the Python web process at once.
        with db.cursor(name='compact_review_input') as cur:
            cur.itersize = 4
            cur.execute(f"""SELECT b.behavior_id,b.api,b.result_code,b.features,
                    p.state AS security_state,c.context AS security_context
                FROM {schema}.behaviors b JOIN {schema}.behavior_payloads p USING(behavior_id)
                LEFT JOIN {schema}.request_context c USING(behavior_id)
                WHERE b.stream_id=%s AND b.behavior_id=ANY(%s)""", (stream,list(projections)))
            for record in cur:
                bid = record['behavior_id']
                for (service, axis), value in verified_targets(record, projections[bid]).items():
                    targets[bid, service, axis] = value
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
            cutoff = f['start_ns'] + FIVE
            if f['method'] == 'long_target_enumeration' and row['observed_at_ns'] is not None:
                cutoff = (row['observed_at_ns'] // FIVE + 1) * FIVE
            if (target and target[1]<cutoff and row['session_id']==f['session_id']
                    and row['observed_at_ns'] is not None and start<=row['observed_at_ns']<end):
                value = target[0]
                if value not in data['targets']:
                    data['targets'].append(value)
            data['rows'].append(dict(bid=bid,request_id=raw[0] if raw else row['request_id'],
                                     api=row['api'],service=f['service'] if value is not None else row['service'],at=row['observed_at_ns'],
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
