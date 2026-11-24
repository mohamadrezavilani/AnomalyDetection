"""A reviewed composite dispatcher proof, scoped to the exact v3 Core branch.

InvoiceRegisterHandler.V3_LandLinePhoneBillsExport constructs the v3 command.
Its query has FixedLineNumber/Final/Cycle and its provider call uses the same
number/cycle and MidTerm=!Final. V1/V2 export handlers use another query model.
A provider name or a numeric service ID alone is never this proof.
"""
API = 'Services.v1/InvoiceRegister'
SERVICE = 'Services.v3/LandLinePhoneBillsExport'
PATH = 'ClientAyanCoInquiry.FixedLineBillInquiryGetBillImage'
SQL = 'DBPath.pishkhan24.application.ud_prc_inquiryInvoiceResult2'
POLICY = 'fixed-line-export-composite-1'
REFUSALS = ('G00002', 'G00003', 'G00010', 'GR0004')


def verified(state):
    roots = state.get('roots', [])
    if (state.get('issues') or state.get('apis', []) != [API]
            or len(roots) != 1 or roots[0]['api'] != API
            or type(roots[0].get('at_ns')) is not int or roots[0].get('code') in REFUSALS
            or len(state.get('sessions', [])) > 1):
        return False
    dispatch = state.get('dispatch', [])
    if (any(d['kind'] == 'action' and d['value'] != SERVICE for d in dispatch)
            or len({d['value'] for d in dispatch if d['kind'] == 'service_request'}) > 1
            or any(e['path'] in (PATH, SQL) for e in state.get('parse_errors', []))):
        return False
    inputs = state.get('inputs', [])
    outputs = state.get('outputs', [])
    query = [v for v in inputs if v['path'] == SQL]
    provider = [v for v in inputs if v['path'] == PATH]
    response = [v for v in outputs if v['path'] == PATH]
    if (len(query) != 1 or len(provider) != 1 or len(response) != 1
            or any(v['path'].startswith('ClientAyanCoInquiry.') and v['path'] != PATH for v in inputs + outputs)):
        return False
    q, p, o = query[0], provider[0], response[0]
    if (any(v.get('representation') == 'FEATURES_ONLY_V1' or type(v.get('observed_at_ns')) is not int
            or v['observed_at_ns'] > roots[0]['at_ns'] for v in (q, p, o))
            or p['observed_at_ns'] != o['observed_at_ns']):
        return False
    q, p, o = q.get('value'), p.get('value'), o.get('value')
    if not (isinstance(p, list) and len(p) == 1 and isinstance(o, list) and len(o) == 1):
        return False
    p, o = p[0], o[0]
    return bool(isinstance(q, dict) and isinstance(p, dict) and isinstance(o, dict)
                and set(q) <= {'FixedLineNumber', 'Final', 'Cycle'}
                and isinstance(q.get('FixedLineNumber'), str) and q['FixedLineNumber'].strip()
                and p.get('FixedLineNumber') == q['FixedLineNumber']
                and type(q.get('Final')) is bool and type(p.get('MidTerm')) is bool
                and p['MidTerm'] != q['Final'] and p.get('Cycle') == q.get('Cycle')
                and isinstance(o.get('Status'), dict) and isinstance(o['Status'].get('Code'), str))


def proof_sql():
    """Same bounded proof for legacy rows, after a primary-key payload lookup."""
    return f"""p.state->'apis'=jsonb_build_array('{API}') AND p.state->'issues'='[]'::jsonb
        AND jsonb_array_length(p.state->'sessions')<=1 AND jsonb_array_length(p.state->'roots')=1
        AND p.state->'roots'->0->>'api'='{API}'
        AND COALESCE(p.state->'roots'->0->>'code','') NOT IN {str(REFUSALS)}
        AND jsonb_typeof(p.state->'roots'->0->'at_ns')='number'
        AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p.state->'dispatch') d
            WHERE d->>'kind'='action' AND d->>'value'<>'{SERVICE}')
        AND (SELECT count(DISTINCT d->>'value') FROM jsonb_array_elements(p.state->'dispatch') d
            WHERE d->>'kind'='service_request')<=1
        AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p.state->'parse_errors') e WHERE e->>'path' IN ('{PATH}','{SQL}'))
        AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements((p.state->'inputs')||(p.state->'outputs')) v
            WHERE starts_with(v->>'path','ClientAyanCoInquiry.') AND v->>'path'<>'{PATH}')
        AND (SELECT count(*) FROM jsonb_array_elements(p.state->'inputs') v WHERE v->>'path'='{SQL}')=1
        AND (SELECT count(*) FROM jsonb_array_elements(p.state->'inputs') v WHERE v->>'path'='{PATH}')=1
        AND (SELECT count(*) FROM jsonb_array_elements(p.state->'outputs') v WHERE v->>'path'='{PATH}')=1
        AND EXISTS(SELECT 1 FROM jsonb_array_elements(p.state->'inputs') q,
            jsonb_array_elements(p.state->'inputs') i,jsonb_array_elements(p.state->'outputs') o
            WHERE q->>'path'='{SQL}' AND i->>'path'='{PATH}' AND o->>'path'='{PATH}'
            AND jsonb_typeof(q->'value')='object'
            AND ((q->'value')-'FixedLineNumber'-'Final'-'Cycle')='{{}}'::jsonb
            AND jsonb_typeof(q->'value'->'FixedLineNumber')='string' AND trim(q->'value'->>'FixedLineNumber')<>''
            AND jsonb_typeof(q->'value'->'Final')='boolean'
            AND jsonb_array_length(CASE WHEN jsonb_typeof(i->'value')='array' THEN i->'value' ELSE '[]'::jsonb END)=1
            AND jsonb_array_length(CASE WHEN jsonb_typeof(o->'value')='array' THEN o->'value' ELSE '[]'::jsonb END)=1
            AND jsonb_typeof(i->'value'->0->'MidTerm')='boolean'
            AND i->'value'->0->'MidTerm'<>q->'value'->'Final'
            AND i->'value'->0->'FixedLineNumber'=q->'value'->'FixedLineNumber'
            AND COALESCE(i->'value'->0->'Cycle','null'::jsonb)=COALESCE(q->'value'->'Cycle','null'::jsonb)
            AND jsonb_typeof(o->'value'->0->'Status'->'Code')='string'
            AND i->'observed_at_ns'=o->'observed_at_ns'
            AND NOT EXISTS(SELECT 1 FROM (VALUES(q),(i),(o)) checks(v)
                WHERE COALESCE(v->>'representation','')='FEATURES_ONLY_V1'
                OR jsonb_typeof(v->'observed_at_ns') IS DISTINCT FROM 'number'
                OR (v->'observed_at_ns')>(p.state->'roots'->0->'at_ns')))
    """


def verified_sql(schema):
    return f"""CASE WHEN b.api='{API}' AND b.features->>'service_binding'='UNRESOLVED_DISPATCH'
        AND COALESCE(b.result_code,'') NOT IN {str(REFUSALS)}
        THEN EXISTS(SELECT 1 FROM {schema}.behavior_payloads p WHERE p.behavior_id=b.behavior_id AND {proof_sql()})
        ELSE false END"""
