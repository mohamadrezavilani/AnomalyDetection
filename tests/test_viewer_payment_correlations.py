"""Four owner scenarios, source conflicts, late evidence and scoped upgrades."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from p24_foundation.payment_correlation import correlation_facts, STATUS_AXIS
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB, token
from p24_foundation.viewer_online import initialize_live, bind_stream, publish_capture, FIVE_NS, iso
from p24_foundation.viewer_correlation_sync import sync_payment_correlations
from tools.qualify_viewer_online import projection_digest
from tests.test_viewer_online import START, verified_file

I, B, B2, B3, FEE, PAY, PAY2 = [str(x) * 32 for x in range(1, 8)]
SESSION = 'A' * 32


def event(n, request, call, message, *, session=SESSION, start=START):
    return dict(_source_id='correlation-test:' + str(n), RequestID=request, Session=session,
                IP='192.0.2.10', CallPath=call, message=message, level='Info',
                **{'@timestamp': iso(start + (n % 250 + 1) * 1_000_000_000)})


def correlation(n, request, relation, body, *, caller=None, session=SESSION, start=START):
    from p24_foundation.payment_correlation import EMITTERS
    return event(n, request, (caller or EMITTERS[relation][0]) + ' Line:41',
                 'correlation: ' + relation + ' \r\n ' + json.dumps(body), session=session, start=start)


def scenario(*, paid=True, bills=(B,), bill_pay=True, status='Success', api='TrafficFinesCarNoDetails'):
    rows = [event(1, 'inquiry', 'Services.v1/' + api + ' Line:1', 'POST (G00000 | successful)'),
            event(2, 'inquiry', 'DBPath.pishkhan24.application.ud_prc_invoiceInfo',
                  '(Command Text: ud_prc_invoiceInfo)(Code: 1)(Result: Ok)(SQL Parameters: @invoiceUniqueID=' + I + ')')]
    if bills:
        rows.append(correlation(3, 'inquiry', 'InvoiceID-BillUniqueIDs', dict(invoiceID=I, BillUniqueIDs=list(bills))))
    if paid:
        rows.extend([correlation(4, 'fee', 'InvoiceID-PaymentKey', dict(InvoiceID=I, PaymentKey=FEE)),
                     event(5, 'fee', 'Core.v1/InvoicePayment Line:1', 'POST (G00000 | successful)'),
                     correlation(6, 'fee-result', 'PaymentKey-Status', dict(PaymentKey=FEE, Status='Success'), session='N/A')])
    if bill_pay:
        rows.extend([correlation(7, 'bill-payment', 'BillUniqueIDs-PaymentKey', dict(BillUniqueIDs=list(bills), PaymentKey=PAY)),
                     event(8, 'bill-payment', 'Core.v1/BillsPayment Line:1', 'POST (G00000 | successful)')])
        if status:
            rows.append(correlation(9, 'bill-result', 'PaymentKey-Status', dict(PaymentKey=PAY, Status=status), session='N/A'))
    return rows


class CorrelationParserTests(unittest.TestCase):
    def test_exact_payload_field_aliases_and_array_positions(self):
        facts = correlation_facts(correlation(1, 'r', 'InvoiceID-BillUniqueIDs', dict(invoiceID=I, BillUniqueIDs=[B, B2])))
        self.assertEqual([x[4] for x in facts['identifiers']], [I, B, B2])
        self.assertEqual(facts['edges'][1][-1], 'message.correlation.invoiceID+BillUniqueIDs[1]')
        upper = correlation_facts(correlation(2, 'r', 'InvoiceID-BillUniqueIDs', dict(InvoiceID=I, BillUniqueIDs=[])))
        self.assertIsNotNone(upper)

    def test_header_inside_provider_text_and_wrong_emitter_cannot_establish_links(self):
        good = correlation(1, 'r', 'InvoiceID-PaymentKey', dict(InvoiceID=I, PaymentKey=PAY))
        self.assertIsNotNone(correlation_facts(good))
        for raw in (dict(good, CallPath='ClientAyanCoPaymentGateway.PaymentInfo Line:1'),
                    dict(good, message='Output: ' + good['message']),
                    dict(good, message=good['message'] + ' trailing text')):
            self.assertIsNone(correlation_facts(raw))

    def test_ambiguous_alias_duplicate_keys_and_invalid_types_are_not_positive_evidence(self):
        raw = correlation(1, 'r', 'InvoiceID-PaymentKey', dict(InvoiceID=I, PaymentKey=PAY))
        prefix = 'correlation: InvoiceID-PaymentKey\n'
        for body in ('{"InvoiceID":"' + I + '","InvoiceID":"' + B + '","PaymentKey":"' + PAY + '"}',
                     json.dumps(dict(InvoiceID=I, invoiceID=B, PaymentKey=PAY)),
                     json.dumps(dict(InvoiceID=True, PaymentKey=PAY)),
                     json.dumps(dict(InvoiceID=I, PaymentKey=42))):
            self.assertIsNone(correlation_facts(dict(raw, message=prefix + body)))

    def test_all_three_observed_status_emitters_and_unknown_status_retained(self):
        for caller in ('PaymentCallbackHandler.Execute', 'WalletPaymentHandler.Execute', 'EwanoPaymentHandler.VerifyRequest'):
            facts = correlation_facts(correlation(1, 'r', 'PaymentKey-Status', dict(PaymentKey=PAY, Status='FutureStatus'), caller=caller))
            self.assertEqual(facts['states'], [(STATUS_AXIS, 'FutureStatus', 'message.correlation.Status')])


class ViewerPaymentCorrelationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.keys = self.root / 'keys.json'
        generate_keys(self.keys)
        self.opts = dict(sqlite_path=self.root / 'viewer.db', keys_path=self.keys)
        self.db = ViewerDB(**self.opts)
        self.addCleanup(self.db.close)
        self.db.init()
        initialize_live(self.db)
        bind_stream(self.db, start_ns=START, stream_key='correlation-tests')
        self.sequence = 0

    def publish(self, rows, *, start=START, mode='forward', fault=None):
        self.sequence += 1
        path = verified_file(self.root / (str(self.sequence) + '.gz'), rows, start)
        return publish_capture(self.db, path, start, start + FIVE_NS, mode=mode, fault=fault)

    def card(self, request='inquiry'):
        return self.db.service_payment_journey(token(self.db.keys, 'request', request))

    def group(self, request='inquiry'):
        return self.card(request)['invoices'][0]

    def test_free_lookup_without_bill_or_payment_remains_one_main_behavior(self):
        self.publish([event(1, 'rates', 'Public.v1/ExchangeCurrency Line:1', 'POST (G00000 | successful)')])
        self.assertIsNone(self.card('rates'))
        self.assertEqual(self.db.semantic_sessions()['total'], 1)

    def test_free_water_query_produces_bill_and_does_not_invent_a_payment(self):
        self.publish(scenario(paid=False, bill_pay=False, api='WaterBills'))
        group = self.group()
        self.assertEqual(group['invoice_id'], I)
        self.assertEqual([x['bill_unique_id'] for x in group['bills']], [B])
        self.assertEqual(group['inquiry_payments'], [])
        self.assertEqual(group['bill_payments'], [])

    def test_paid_postal_query_without_bill_keeps_fee_result_separate(self):
        self.publish(scenario(bills=(), bill_pay=False, api='PostPackagesStatus'))
        group = self.group()
        self.assertEqual([x['outcome'] for x in group['inquiry_payments']], ['success'])
        self.assertEqual(group['bills'], [])
        self.assertEqual(group['bill_payments'], [])

    def test_paid_inquiry_and_bill_payment_are_children_of_original_service(self):
        self.publish(scenario())
        group = self.group()
        self.assertEqual(group['sources'][0]['api'], 'Services.v1/TrafficFinesCarNoDetails')
        self.assertEqual([x['payment_key'] for x in group['inquiry_payments']], [FEE])
        self.assertEqual([x['payment_key'] for x in group['bill_payments']], [PAY])
        self.assertEqual(self.db.semantic_sessions()['total'], 1)
        active = self.db.all("SELECT request_key FROM viewer_semantic_occurrences WHERE state='active'")
        self.assertEqual([r['request_key'] for r in active], [token(self.db.keys, 'request', 'inquiry')])
        callback = self.db.one('SELECT session_key FROM viewer_requests WHERE request_key=?', (token(self.db.keys, 'request', 'bill-result'),))
        self.assertIsNone(callback['session_key'])
        self.assertEqual(self.group('bill-result')['sources'], group['sources'])

    def test_three_bills_are_one_payment_and_multiple_payment_keys_are_not_collapsed(self):
        rows = scenario(paid=False, bills=(B, B2, B3))
        rows.append(correlation(12, 'retry', 'BillUniqueIDs-PaymentKey', dict(BillUniqueIDs=[B2], PaymentKey=PAY2)))
        self.publish(rows)
        group = self.group()
        self.assertEqual(len(group['bills']), 3)
        self.assertEqual(len(group['bill_payments']), 2)
        by_key = {p['payment_key']: p for p in group['bill_payments']}
        self.assertEqual(by_key[PAY]['targets'], [B, B2, B3])
        self.assertEqual(by_key[PAY2]['targets'], [B2])
        self.assertEqual(by_key[PAY2]['outcome'], 'unobserved')

    def test_repeated_same_relation_retains_witnesses_without_another_payment(self):
        rows = scenario()
        rows.append(correlation(14, 'fee-retry', 'InvoiceID-PaymentKey', dict(InvoiceID=I, PaymentKey=FEE)))
        self.publish(rows)
        fee = self.group()['inquiry_payments']
        self.assertEqual(len(fee), 1)
        self.assertEqual(len(fee[0]['evidence']), 2)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_raw_events')['n'], len(rows))

    def test_failed_unknown_and_competing_statuses_never_become_success(self):
        rows = scenario(status='Failed')
        rows.append(correlation(15, 'future-status', 'PaymentKey-Status', dict(PaymentKey=PAY2, Status='FutureStatus')))
        self.publish(rows)
        self.assertEqual(self.group()['bill_payments'][0]['outcome'], 'failed')
        self.assertEqual(self.card('future-status')['unresolved_payments'][0]['outcome'], 'unknown')
        late = correlation(16, 'another-status', 'PaymentKey-Status', dict(PaymentKey=PAY, Status='Success'), start=START + FIVE_NS)
        self.publish([late], start=START + FIVE_NS)
        payment = self.group()['bill_payments'][0]
        self.assertEqual(payment['outcome'], 'multiple_statuses')
        self.assertEqual(payment['status_values'], ['Failed', 'Success'])

    def test_cross_window_late_status_manual_recheck_preserves_cursor_and_main_anchor(self):
        rows = scenario(status=None)
        self.publish(rows)
        self.publish([], start=START + FIVE_NS)
        cursor = self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns']
        anchors = self.db.all('SELECT * FROM viewer_semantic_session_heads')
        self.assertEqual(self.group()['bill_payments'][0]['outcome'], 'unobserved')
        late = correlation(17, 'late-callback', 'PaymentKey-Status', dict(PaymentKey=PAY, Status='Success'), session='N/A')
        self.publish(rows + [late], mode='manual_recheck')
        self.assertEqual(self.group()['bill_payments'][0]['outcome'], 'success')
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'], cursor)
        self.assertEqual(self.db.all('SELECT * FROM viewer_semantic_session_heads'), anchors)

    def test_other_request_origin_version_conflict_retracts_success(self):
        rows = scenario()
        self.publish(rows)
        self.assertEqual(self.group()['bill_payments'][0]['outcome'], 'success')
        conflict = copy.deepcopy(rows[-1])
        conflict['RequestID'] = 'competing-request'
        conflict['@timestamp'] = iso(START + FIVE_NS + 1_000_000_000)
        conflict['message'] = conflict['message'].replace('Success', 'Failed')
        self.publish([conflict], start=START + FIVE_NS)
        self.assertEqual(self.group()['bill_payments'][0]['outcome'], 'unobserved')

    def test_same_literal_other_kind_and_shared_basket_do_not_link_invoice(self):
        rows = scenario(paid=False, bill_pay=False)
        rows.extend([correlation(18, 'unrelated', 'PaymentKey-Status', dict(PaymentKey=I, Status='Success'), session=SESSION),
                     event(19, 'unrelated', 'DBPath.pishkhan24.application.ud_prc_basketGet',
                           '(Command Text: ud_prc_basketGet)(Code: 1)(Result: Ok)(SQL Parameters: @basketID=' + B + ')')])
        self.publish(rows)
        self.assertEqual(self.card('unrelated')['invoices'], [])
        self.assertEqual(self.group()['bill_payments'], [])

    def test_one_payment_can_cover_bills_from_two_independent_services_without_merging_them(self):
        rows = scenario(paid=False, bills=(B,))
        other_invoice = 'A' * 32
        rows.extend([
            event(31, 'other-inquiry', 'Services.v1/ElectricBills Line:1', 'POST (G00000 | successful)'),
            correlation(32, 'other-inquiry', 'InvoiceID-BillUniqueIDs', dict(invoiceID=other_invoice, BillUniqueIDs=[B2])),
            correlation(33, 'batch-targets', 'BillUniqueIDs-PaymentKey', dict(BillUniqueIDs=[B, B2], PaymentKey=PAY)),
        ])
        self.publish(rows)
        original = self.group()
        other = self.group('other-inquiry')
        self.assertEqual(original['invoice_id'], I)
        self.assertEqual(other['invoice_id'], other_invoice)
        self.assertEqual(original['bill_payments'][0]['targets'], [B])
        self.assertEqual(other['bill_payments'][0]['targets'], [B2])
        reverse = self.card('bill-result')
        self.assertEqual({g['invoice_id'] for g in reverse['invoices']}, {I, other_invoice})
        active = self.db.one("SELECT COUNT(*) AS n FROM viewer_semantic_occurrences WHERE state='active'")['n']
        self.assertEqual(active, 2)

    def test_failure_before_commit_is_atomic_and_incremental_matches_full(self):
        self.publish(scenario(status=None))
        before = projection_digest(self.db)
        cursor = self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns']
        late = correlation(20, 'status', 'PaymentKey-Status', dict(PaymentKey=PAY, Status='Success'), start=START + FIVE_NS)
        def fault(stage):
            if stage == 'before_commit':
                raise RuntimeError('test_rollback')
        with self.assertRaisesRegex(RuntimeError, 'test_rollback'):
            self.publish([late], start=START + FIVE_NS, fault=fault)
        self.assertEqual(projection_digest(self.db), before)
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'], cursor)
        self.publish([late], start=START + FIVE_NS)
        incremental = projection_digest(self.db)
        self.db.rebuild(); self.db.rebuild_payment_contract(); self.db.build_semantic_index()
        self.assertEqual(projection_digest(self.db), incremental)

    def test_truncated_status_list_cannot_assert_final_success(self):
        rows = scenario()
        for n in (21, 22, 23):
            rows.append(correlation(n, 'repeat-' + str(n), 'PaymentKey-Status', dict(PaymentKey=PAY, Status='Success'), session='N/A'))
        self.publish(rows)
        self.db.CORRELATION_READ_LIMIT = 2
        card = self.card('bill-result')
        self.assertTrue(card['truncated'])
        found = [p for group in card['invoices'] for p in group['bill_payments']]
        found += card['unresolved_payments']
        self.assertTrue(found)
        self.assertEqual(next(p for p in found if p['payment_key'] == PAY)['outcome'], 'partial_evidence')

    def test_request_and_action_render_original_api_and_payment_results(self):
        self.publish(scenario(bills=(B, B2, B3)))
        from p24_foundation.viewer_ui import create_viewer_app
        client = create_viewer_app(self.opts).test_client()
        key = token(self.db.keys, 'request', 'inquiry')
        for prefix in ('/request/', '/action/'):
            response = client.get(prefix + key, base_url='http://127.0.0.1')
            self.assertEqual(response.status_code, 200)
            html = response.get_data(as_text=True)
            panel = html.split('id="service-payment-journey"', 1)[1].split('</section>', 1)[0]
            for value in ('Services.v1/TrafficFinesCarNoDetails', I, B, B2, B3, FEE, PAY, 'Success'):
                self.assertIn(value, panel)
            self.assertEqual(panel.count('PaymentKey:'), 2)

    def test_sync_existing_correlations_preserves_raw_roles_cursor_and_is_idempotent(self):
        with patch('p24_foundation.viewer_contract.correlation_facts', return_value=None):
            self.publish(scenario())
        raw = self.db.all('SELECT * FROM viewer_raw_events ORDER BY origin_key,version_key')
        roles = self.db.all('SELECT * FROM viewer_service_roles ORDER BY service_path')
        anchors = self.db.all('SELECT * FROM viewer_semantic_occurrences ORDER BY request_key')
        cursor = self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns']
        first = sync_payment_correlations(self.db, START)
        self.assertEqual(first['status'], 'UPDATED')
        self.assertEqual(self.group()['bill_payments'][0]['outcome'], 'success')
        generation = self.db.one('SELECT generation FROM viewer_live_state')['generation']
        second = sync_payment_correlations(self.db, START)
        self.assertEqual(second['status'], 'NO_CHANGE')
        self.assertEqual(self.db.one('SELECT generation FROM viewer_live_state')['generation'], generation)
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'], cursor)
        self.assertEqual(self.db.all('SELECT * FROM viewer_raw_events ORDER BY origin_key,version_key'), raw)
        self.assertEqual(self.db.all('SELECT * FROM viewer_service_roles ORDER BY service_path'), roles)
        self.assertEqual(self.db.all('SELECT * FROM viewer_semantic_occurrences ORDER BY request_key'), anchors)

    def test_sync_failure_rolls_back_projection_and_generations(self):
        with patch('p24_foundation.viewer_contract.correlation_facts', return_value=None):
            self.publish(scenario())
        before = projection_digest(self.db)
        state = self.db.one('SELECT * FROM viewer_live_state')
        def fault(stage):
            raise RuntimeError('sync_rollback')
        with self.assertRaisesRegex(RuntimeError, 'sync_rollback'):
            sync_payment_correlations(self.db, START, fault=fault)
        self.assertEqual(projection_digest(self.db), before)
        self.assertEqual(self.db.one('SELECT * FROM viewer_live_state'), state)

    def test_sync_empty_or_oversized_scope_cannot_move_cursor(self):
        self.publish(scenario())
        state = self.db.one('SELECT * FROM viewer_live_state')
        result = sync_payment_correlations(self.db, START + 10 * FIVE_NS)
        self.assertEqual(result['status'], 'NO_CAPTURED_CANDIDATES')
        with self.assertRaisesRegex(ValueError, 'correlation_sync_scope_too_large'):
            sync_payment_correlations(self.db, START, max_requests=1)
        self.assertEqual(self.db.one('SELECT * FROM viewer_live_state'), state)

    def test_native_qualification_driver_flow_on_sqlite_is_not_native_evidence(self):
        # Exercise directory creation, ID rewriting, four windows and rollback.
        # Only the native external connection is mocked; no native PASS claimed.
        import tools.qualify_viewer_payment_correlations as qualification
        def sqlite_viewer(**opts):
            return ViewerDB(sqlite_path=self.root / 'qualification-transport.db', keys_path=opts['keys_path'])
        with patch('psycopg.connect') as admin, patch.object(qualification, 'ViewerDB', side_effect=sqlite_viewer):
            result = qualification.qualify(dict(dbname='p24_design_viewer'), self.root / 'native-driver-offline')
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(len(result['checks']), 9)
        self.assertEqual(admin.call_args.kwargs['dbname'], 'postgres')
        self.assertRegex(result['database'], r'^p24_design_corr_[a-f0-9]{8}_qualification$')


if __name__ == '__main__':
    unittest.main()
