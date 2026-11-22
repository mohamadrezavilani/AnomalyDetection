"""Bounded repair of one proven dispatcher request using its complete source window."""
from compact_behavior import FIVE, FEATURES
from compact_behavior.extract import identity, behavior_id, materialize
from compact_behavior.services import routes, operation_role


def inspect(store, stream, request_id, expected_service, *, access_denied=False):
    if expected_service not in routes() or operation_role(
            'Services.v1/InvoiceRegister', expected_service,
            'SAME_REQUEST_REVIEWED_DISPATCH') not in ('business', 'user_management'):
        raise ValueError('reviewed_business_dispatch_required')
    key = identity(request_id)
    row = store.conn.execute(f'''SELECT request_id,api,observed_at_ns,revision,features
        FROM {store.schema}.behaviors WHERE stream_id=%s AND behavior_id=%s''',
        (stream, behavior_id(stream, key))).fetchone()
    if not row or row['api'] != 'Services.v1/InvoiceRegister' or row['observed_at_ns'] is None:
        raise ValueError('published_dispatch_behavior_required')
    f = row['features']
    ready = (f.get('version') == FEATURES and f.get('service_key') == expected_service
             and f.get('service_binding') == 'SAME_REQUEST_REVIEWED_DISPATCH'
             and f.get('service_rate_eligible') is True
             and f.get('operation_role') in ('business', 'user_management'))
    attempt = f.get('access_denied_attempt') or {}
    classified = (f.get('version') == FEATURES and attempt.get('verified') is True
                  and attempt.get('service') == expected_service
                  and attempt.get('result_code') == 'G00010'
                  and attempt.get('stage') == 'ACCESS_DENIED_BEFORE_CONFIRMED_DISPATCH'
                  and not f.get('service_rate_eligible') and not f.get('service_key'))
    return dict(request_id=key, expected_service=expected_service,
                ready_for_requested_repair=classified if access_denied else ready,
                access_denied_classified=classified,
                dedicated_access_denial_ad='NOT_IMPLEMENTED',
                start_ns=row['observed_at_ns']//FIVE*FIVE, revision=row['revision'],
                stored_service=f.get('service_key'), stored_binding=f.get('service_binding'),
                stored_role=f.get('operation_role'), ready_for_rate_analysis=ready,
                input_eligibility=f.get('input_feature_eligibility'),
                output_eligibility=f.get('output_feature_eligibility'))


class DispatchWindowWriter:
    def __init__(self, store, request_id, service, start, *, access_denied=False):
        self.store, self.request_id, self.service = store, identity(request_id), service
        self.start, self.limits = start, store.limits
        self.access_denied = access_denied

    def publish(self, stream, start, end, states, count):
        from tools.Repair_Compact_Sample_Roles import republish
        if start != self.start or end != start+FIVE:
            raise ValueError('repair_window_mismatch')
        state = states.get(self.request_id)
        body = materialize(stream, state) if state else None
        if self.access_denied:
            attempt = body['features'].get('access_denied_attempt', {}) if body else {}
            proven = (attempt.get('verified') is True and attempt.get('service') == self.service
                      and attempt.get('stage') == 'ACCESS_DENIED_BEFORE_CONFIRMED_DISPATCH')
        else:
            proven = body and (body.get('api'), body['features'].get('service_key'),
                              body['features'].get('service_binding'),
                              body['features'].get('service_rate_eligible')) == (
                'Services.v1/InvoiceRegister', self.service, 'SAME_REQUEST_REVIEWED_DISPATCH', True)
        if not proven:
            raise ValueError('source_does_not_prove_expected_dispatch')
        with self.store.conn.transaction():
            result = republish(self.store, stream, start, end, states, count, [self.request_id])
            if not inspect(self.store, stream, self.request_id, self.service, access_denied=self.access_denied)['ready_for_requested_repair']:
                raise ValueError('dispatch_repair_not_applied')
        return result
