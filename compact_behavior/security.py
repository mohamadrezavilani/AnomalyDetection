"""Same-request terminal refusals; requested destinations are never executions."""
import hashlib
import json
from .context import VERSION as CONTEXT_VERSION
from .services import operation_role, foreground_apis
from . import inquiry

POLICY = 'verified-access-attempt-1'
FIELD = 'security_attempt'
DISPATCH = 'Services.v1/InvoiceRegister'
PAIRS = {
    ('G00010', 'UserAccessObjectsDoesNotContainAccessObject'): 'access_denied',
    ('G00002', 'SessionIsNotValid'): 'invalid_session',
    ('G00003', 'NullCheckError'): 'validation_rejection',
}
DOCUMENTS = [
    dict(name='Inquiry-V4.1.0.pdf', page=137, printed_page=136,
         sha256='2abcc44fa1f2587060d5d336871a7b8b5d928173d74c843b8c66134a0ccece60'),
    dict(name='Payment-V3.0.0.pdf', page=71, printed_page=70,
         sha256='5e773f3fcf253a77f5aa37192342cbd1a796f2e4334514d08a099419bd535767'),
]


def fingerprint(kind, value):
    return hashlib.sha256(json.dumps([POLICY, kind, value], separators=(',', ':')).encode()).hexdigest()


def network(context, at):
    """Only unambiguous, dated log/authorization observations, never body IPs."""
    if context.get('version') != CONTEXT_VERSION or any(x.startswith('ip_') for x in context.get('limited', ())):
        return None
    entries = context.get('values', {}).get('ip', ())
    if len(entries) != 1:
        return None
    entry = entries[0]
    if (entry.get('undated') or type(entry.get('first_ns')) is not int
            or entry['first_ns'] > at
            or not any(x in ('log.IP', 'sql.access.@ipaddress') for x in entry.get('sources', ()))):
        return None
    return fingerprint('ip', entry['value'])


def project(state, context=None):
    roots = state.get('roots', ())
    apis = foreground_apis(state.get('apis', ()), roots)
    if len(roots) != 1 or len(apis) != 1:
        return None
    root = roots[0]
    api = apis[0]
    kind = PAIRS.get((root.get('code'), root.get('symbol')))
    if (not kind or root.get('api') != api or type(root.get('at_ns')) is not int
            or operation_role(api) in ('system', 'unknown') and api != DISPATCH
            or any(x in state.get('issues', ()) for x in (
                'operation_field_conflict', 'message_field_conflict', 'timestamp_unavailable',
                'request_id_conflicting', 'prior_fragments_expired'))):
        return None
    dispatch = state.get('dispatch', ())
    if any(x.get('kind') == 'service_request' for x in dispatch):
        return None  # Competing execution evidence must be reviewed separately.
    # The retained action grammar maps service-dispatch destinations to
    # Services.*. Direct Core/Ewano APIs have their own public root; do not
    # reinterpret their authorization action as an unknown Services endpoint.
    actions = {x['value'] for x in dispatch if x.get('kind') == 'action'} if api == DISPATCH else set()
    if len(actions) > 1:
        return None
    requested = next(iter(actions), None)
    if requested and operation_role(requested) == 'unknown':
        return None
    sessions = state.get('sessions', ())
    unique_session = (sessions[0] if len(sessions) == 1
                      and 'session_field_conflict' not in state.get('issues', ()) else None)
    value = dict(policy=POLICY, kind=kind, api=api, scope=requested or api,
                 requested_service=requested, result_code=root['code'], symbol=root['symbol'],
                 at_ns=root['at_ns'], stage='REJECTED_BEFORE_CONFIRMED_EXECUTION')
    if kind != 'invalid_session':
        value.update(cohort_type='session', cohort_key=unique_session)
    else:
        value.update(cohort_type='ip', cohort_key=network(context or state.get('request_context', {}), root['at_ns']),
                     token_fingerprint=fingerprint('unverified_token', unique_session) if unique_session else None)
    return value


def legacy_rows(rows):
    """The SQL cursor fetches retained state only for the two candidate codes."""
    for row in rows:
        state = row.pop('security_state', None)
        context = row.pop('security_context', None)
        if state is not None:
            if (row.get('api') in ('Services.v1/ElectricBills','Services.v2/GasBills')
                    or row.get('api')=='Services.v1/InvoiceRegister' and row['features'].get('service_binding')=='UNRESOLVED_DISPATCH'
                    and row.get('result_code') not in ('G00002','G00003','G00010','GR0004')
                    or row['features'].get('service_key') in inquiry.ROUTES
                    and inquiry.POLICY not in row['features']):
                from .extract import materialize
                body=materialize('projection',state,context=context)
                if body and body['api']==row['api']:
                    row['features']=body['features']
            attempt = project(state, context)
            if attempt:
                row['features'] = dict(row['features'], **{FIELD: attempt})
        yield row


def input_sql(schema, *, previous=False):
    # LIMIT 1 retains parameterized primary-key lookups, including large tables.
    reviewed=','.join("'"+x+"'" for x in sorted(inquiry.ROUTES))
    candidate = f"""(b.result_code IN ('G00002','G00003','G00010') AND NOT (b.features ? 'security_attempt')
        OR b.api='Services.v1/InvoiceRegister' AND b.features->>'service_binding'='UNRESOLVED_DISPATCH'
            AND COALESCE(b.result_code,'') NOT IN ('G00002','G00003','G00010','GR0004')
        OR b.features->>'service_key' IN ({reviewed})
            AND NOT (b.features ? 'inquiry_subjects_v1'))"""
    features='b.features'
    if previous:
        keys=('version','service_key','service_binding','session_eligible','service_rate_eligible',
              'input_asof_ns','input_feature_eligibility','inquiry_subjects_v1','security_attempt','rejected_attempt')
        features="jsonb_build_object("+','.join("'"+k+"',b.features->'"+k+"'" for k in keys)+") AS features"
    return f"""SELECT b.behavior_id,b.session_id,b.result_code,{features},b.kind,b.api,
        b.observed_at_ns,b.reported_duration,p.state AS security_state,c.context AS security_context
        FROM {schema}.behaviors b
        LEFT JOIN LATERAL(SELECT state FROM {schema}.behavior_payloads p
            WHERE p.behavior_id=b.behavior_id AND {candidate} LIMIT 1) p ON true
        LEFT JOIN LATERAL(SELECT context FROM {schema}.request_context c
            WHERE c.behavior_id=b.behavior_id AND p.state IS NOT NULL LIMIT 1) c ON true
        WHERE b.stream_id=%s AND b.observed_at_ns>=%s AND b.observed_at_ns<%s
        {"AND b.session_id=ANY(%s) AND b.features->>'operation_role' NOT IN ('system','support')" if previous else ''}
        ORDER BY b.observed_at_ns,b.behavior_id"""
