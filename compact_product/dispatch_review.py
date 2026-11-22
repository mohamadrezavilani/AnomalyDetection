"""Bounded repair of one proven dispatcher request using its complete source window."""
from compact_behavior import FIVE, FEATURES
from compact_behavior.extract import identity, behavior_id, materialize
from compact_behavior.services import routes, operation_role


def inspect(store, stream, request_id, expected_service):
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
    return dict(request_id=key, expected_service=expected_service,
                start_ns=row['observed_at_ns']//FIVE*FIVE, revision=row['revision'],
                stored_service=f.get('service_key'), stored_binding=f.get('service_binding'),
                stored_role=f.get('operation_role'), ready_for_rate_analysis=ready,
                input_eligibility=f.get('input_feature_eligibility'),
                output_eligibility=f.get('output_feature_eligibility'))


class DispatchWindowWriter:
    def __init__(self, store, request_id, service, start):
        self.store, self.request_id, self.service = store, identity(request_id), service
        self.start, self.limits = start, store.limits

    def publish(self, stream, start, end, states, count):
        from tools.Repair_Compact_Sample_Roles import republish
        if start != self.start or end != start+FIVE:
            raise ValueError('repair_window_mismatch')
        state = states.get(self.request_id)
        body = materialize(stream, state) if state else None
        if not body or (body.get('api'), body['features'].get('service_key'),
                        body['features'].get('service_binding'),
                        body['features'].get('service_rate_eligible')) != (
                'Services.v1/InvoiceRegister', self.service,
                'SAME_REQUEST_REVIEWED_DISPATCH', True):
            raise ValueError('source_does_not_prove_expected_dispatch')
        with self.store.conn.transaction():
            result = republish(self.store, stream, start, end, states, count, [self.request_id])
            if not inspect(self.store, stream, self.request_id, self.service)['ready_for_rate_analysis']:
                raise ValueError('dispatch_repair_not_applied')
        return result
