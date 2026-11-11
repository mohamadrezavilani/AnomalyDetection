"""Indexed Invoice/Bill/Payment navigation; no Session joins or new behaviors."""
from __future__ import annotations
from collections import defaultdict

from .payment_correlation import STATUS_AXIS
from .service_journey import semantic_execution_kind

RELATIONS = ('invoice_targets_fee_payment', 'invoice_produces_bill', 'bill_targets_payment')


class ServicePaymentJourneyMixin:
    CORRELATION_READ_LIMIT = 256

    @staticmethod
    def _correlation_clean(alias, origin='origin_key', version='version_key'):
        # The global fence covers competing versions under OTHER RequestIDs.
        return (f'(SELECT COUNT(*) FROM viewer_events cv WHERE cv.origin_key={alias}.{origin})=1 '
                f'AND EXISTS(SELECT 1 FROM viewer_events ce WHERE ce.origin_key={alias}.{origin} '
                f'AND ce.version_key={alias}.{version}) '
                f'AND NOT EXISTS(SELECT 1 FROM viewer_requests cr WHERE cr.request_key={alias}.request_key AND cr.conflicted=1)')

    def _correlation_rows(self, statement, args, state):
        limit = self.CORRELATION_READ_LIMIT
        rows = self.all(statement + ' LIMIT ?', list(args) + [limit + 1])
        if len(rows) > limit:
            state['truncated'] = True
            state['truncations'] = state.get('truncations', 0) + 1
        return rows[:limit]

    def _correlation_edges(self, relation, column, identities, state):
        identities = sorted(set(identities))
        if not identities:
            return []
        assert column in ('from_typed_id', 'to_typed_id')
        rows = []
        # Keep parameter counts and every page bounded even for multi-Invoice requests.
        for begin in range(0, len(identities), 200):
            batch = identities[begin:begin + 200]
            rows.extend(self._correlation_rows('''SELECT e.*,
                (SELECT ce.callpath FROM viewer_events ce WHERE ce.origin_key=e.evidence_origin
                 AND ce.version_key=e.evidence_version) AS callpath FROM viewer_contract_edges e
                WHERE e.relation_type=? AND e.scope='core_explicit_correlation'
                  AND e.eligibility='explicit_correlation' AND e.''' + column + ' IN (' +
                ','.join('?' for _ in batch) + ') AND ' +
                self._correlation_clean('e', 'evidence_origin', 'evidence_version') +
                ' ORDER BY e.observed_ns,e.edge_key', [relation, *batch], state))
        return rows

    def _correlation_proof(self, row, *, edge=False):
        from .viewer_data import tehran
        key = row['request_key']
        return dict(origin_key=row['evidence_origin'] if edge else row['origin_key'],
                    version_key=row['evidence_version'] if edge else row['version_key'],
                    field_path=row['evidence_path'] if edge else row['field_path'],
                    request_key=key, raw_request_id=self.raw_request_id(key),
                    at_ns=row['observed_ns'] if edge else row['at_ns'],
                    when_fa=tehran(row['observed_ns'] if edge else row['at_ns']),
                    callpath=row.get('callpath'))

    def service_payment_journey(self, request_key):
        """Explicit directed paths only; shared baskets/Session cannot bridge them.

        The panel is current-snapshot evidence. No cached result survives a later
        publication, and a technical payment never updates the semantic anchor.
        """
        state = dict(truncated=False)
        seeds = self._correlation_rows('''SELECT c.* FROM viewer_contract_identifiers c
            WHERE c.request_key=? AND c.issuer='pishkhan24'
              AND c.kind IN ('invoice','bill_unique_id','internal_payment') AND ''' +
            self._correlation_clean('c') + ' ORDER BY c.kind,c.identity_key,c.field_path', [request_key], state)
        invoice_ids = {r['identity_key'] for r in seeds if r['kind'] == 'invoice'}
        bill_ids = {r['identity_key'] for r in seeds if r['kind'] == 'bill_unique_id'}
        payment_ids = {r['identity_key'] for r in seeds if r['kind'] == 'internal_payment'}
        # Reverse entry from the payment/status RequestID, without copying Session.
        reverse_fee = self._correlation_edges(RELATIONS[0], 'to_typed_id', payment_ids, state)
        reverse_bill = self._correlation_edges(RELATIONS[2], 'to_typed_id', payment_ids, state)
        invoice_ids.update(r['from_typed_id'] for r in reverse_fee)
        bill_ids.update(r['from_typed_id'] for r in reverse_bill)
        reverse_invoice = self._correlation_edges(RELATIONS[1], 'to_typed_id', bill_ids, state)
        invoice_ids.update(r['from_typed_id'] for r in reverse_invoice)
        produced = self._correlation_edges(RELATIONS[1], 'from_typed_id', invoice_ids, state)
        fees = self._correlation_edges(RELATIONS[0], 'from_typed_id', invoice_ids, state)
        bill_ids.update(r['to_typed_id'] for r in produced)
        payments = self._correlation_edges(RELATIONS[2], 'from_typed_id', bill_ids, state)
        payment_ids.update(r['to_typed_id'] for r in fees + payments)
        all_ids = invoice_ids | bill_ids | payment_ids
        if not all_ids:
            return None
        labels = {}
        label_batch = max(1, min(200, self.CORRELATION_READ_LIMIT))
        for begin in range(0, len(all_ids), label_batch):
            batch = sorted(all_ids)[begin:begin + label_batch]
            for row in self._correlation_rows('''SELECT DISTINCT c.identity_key,c.kind,c.raw_value
                FROM viewer_contract_identifiers c WHERE c.identity_key IN (''' +
                ','.join('?' for _ in batch) + ') AND ' + self._correlation_clean('c') +
                ' ORDER BY c.identity_key,c.raw_value', batch, state):
                labels[row['identity_key']] = row['raw_value']
        observations = defaultdict(list)
        partial_statuses = set()
        for begin in range(0, len(payment_ids), 200):
            batch = sorted(payment_ids)[begin:begin + 200]
            from .viewer_storage_keys import exact_origin_join
            query = ('''SELECT DISTINCT o.*,c.identity_key FROM viewer_contract_observations o
                JOIN viewer_contract_identifiers c ON '''+exact_origin_join(self,'c','o')+'''
                WHERE c.issuer='pishkhan24' AND c.kind='internal_payment' AND o.axis=?
                  AND c.identity_key IN (''' + ','.join('?' for _ in batch) + ') AND ' +
                self._correlation_clean('o') + ' ORDER BY o.at_ns,o.origin_key,o.version_key')
            previous_truncations = state.get('truncations', 0)
            for row in self._correlation_rows(query, [STATUS_AXIS, *batch], state):
                observations[row['identity_key']].append(dict(value=row['value'], evidence=self._correlation_proof(row)))
            if state.get('truncations', 0) != previous_truncations:
                partial_statuses.update(batch)
        if not (produced or fees or payments or observations or
                any(r['field_path'].startswith('message.correlation.') for r in seeds)):
            return None  # Legacy evidence keeps its existing, separately scoped UI.

        def payment_card(identity, proofs, targets=()):
            seen = observations[identity]
            values = sorted({r['value'] for r in seen})
            outcome = ('success' if values == ['Success'] else 'failed' if values == ['Failed'] else
                       'unobserved' if not values else 'multiple_statuses' if len(values) > 1 else 'unknown')
            if identity in partial_statuses:
                outcome = 'partial_evidence'
            return dict(payment_key=labels.get(identity, identity), identity_key=identity, outcome=outcome,
                        statuses=seen, status_values=values,
                        targets=[labels.get(x, x) for x in sorted(set(targets))],
                        evidence=[self._correlation_proof(row, edge=True) for row in proofs])

        groups = []
        for invoice in sorted(invoice_ids):
            sources = []
            rows = self._correlation_rows('''SELECT DISTINCT r.request_key,r.root_call,r.session_key,
                a.category,COALESCE(sr.reviewed,0) AS role_reviewed
                FROM viewer_contract_identifiers c JOIN viewer_requests r ON r.request_key=c.request_key
                LEFT JOIN viewer_actions a ON a.action_key=r.request_key
                LEFT JOIN viewer_service_roles sr ON (r.root_call=sr.service_path OR r.root_call LIKE sr.service_path || ?)
                WHERE c.identity_key=? AND c.kind='invoice' AND r.conflicted=0 AND ''' +
                self._correlation_clean('c') + ' ORDER BY r.request_key', [' Line:%', invoice], state)
            self.apply_service_contexts(rows)
            for row in rows:
                if semantic_execution_kind(row['root_call'], row['category'], role_reviewed=bool(row['role_reviewed'])) != 'service_execution':
                    continue
                sources.append(dict(request_key=row['request_key'], raw_request_id=self.raw_request_id(row['request_key']),
                                    api=str(row['root_call']).split(' Line:', 1)[0], session_key=row['session_key']))
            own_bills = [r for r in produced if r['from_typed_id'] == invoice]
            own_bill_ids = {r['to_typed_id'] for r in own_bills}
            fee_groups = defaultdict(list)
            bill_groups = defaultdict(list)
            for row in fees:
                if row['from_typed_id'] == invoice:
                    fee_groups[row['to_typed_id']].append(row)
            for row in payments:
                if row['from_typed_id'] in own_bill_ids:
                    bill_groups[row['to_typed_id']].append(row)
            groups.append(dict(invoice_id=labels.get(invoice, invoice), sources=sources,
                bills=[dict(bill_unique_id=labels.get(identity, identity), evidence=[
                    self._correlation_proof(r, edge=True) for r in own_bills if r['to_typed_id'] == identity])
                       for identity in sorted(own_bill_ids)],
                inquiry_payments=[payment_card(identity, rows) for identity, rows in sorted(fee_groups.items())],
                bill_payments=[payment_card(identity, rows, [r['from_typed_id'] for r in rows])
                               for identity, rows in sorted(bill_groups.items())]))
        attached = {p['identity_key'] for group in groups for kind in ('inquiry_payments', 'bill_payments') for p in group[kind]}
        return dict(invoices=groups, unresolved_payments=[payment_card(x, []) for x in sorted(payment_ids - attached)],
                    current_request_key=request_key, truncated=state['truncated'],
                    scope='explicit_core_correlations_current_snapshot', standalone_behavior=False,
                    unique_payment_count=len(payment_ids), financial_settlement='not_inferred')
