"""Payment progression, Iran display times and a narrowly scoped role correction."""
import copy
import json
import unittest
from unittest.mock import patch

from p24_foundation.viewer_data import initial_service_role
from p24_foundation.viewer_display_time import tehran_time
from p24_foundation.viewer_execution_detail import execution_detail
from p24_foundation.viewer_online import resume_recent, SECOND_NS
from p24_foundation.viewer_ui import create_viewer_app
from tests import test_viewer_execution_detail as detail_fixture
from tests import test_viewer_payment_correlations as payment_fixture
from tests.test_viewer_online import START, FIVE_NS


class FlowDisplayTests(unittest.TestCase):
    setUp = detail_fixture.ExecutionDetailTests.setUp
    row = detail_fixture.ExecutionDetailTests.row
    provider = detail_fixture.ExecutionDetailTests.provider
    flow = detail_fixture.ExecutionDetailTests.flow
    postal = detail_fixture.ExecutionDetailTests.postal
    publish = detail_fixture.ExecutionDetailTests.publish
    detail = detail_fixture.ExecutionDetailTests.detail

    def test_fee_and_bill_results_are_visible_in_the_same_flow_and_stay_separate(self):
        self.publish(payment_fixture.scenario(status='Failed'))
        detail = self.detail('inquiry')
        cards = {p['kind']: p for p in detail['payment_cards']}
        self.assertEqual(cards['inquiry_payments']['status'], 'success')
        self.assertEqual(cards['bill_payments']['status'], 'failure')
        self.assertEqual(cards['bill_payments']['targets'], [payment_fixture.B])
        result_steps = {s['kind']: s for s in detail['steps'] if s['kind'].endswith('_result')}
        self.assertEqual(result_steps['inquiry_payments_result']['code'], 'Success')
        self.assertEqual(result_steps['bill_payments_result']['code'], 'Failed')
        self.assertTrue(result_steps['bill_payments_result']['related'])
        self.assertIsNotNone(result_steps['bill_payments_result']['at_ns'])
        self.assertTrue(result_steps['bill_payments_result']['proofs'])
        key = self.db.lookup_request('inquiry')['request_key']
        html = create_viewer_app(self.opts).test_client().get('/request/' + key).get_data(as_text=True)
        self.assertIn('data-step-kind="inquiry_payments_result"', html)
        self.assertIn('data-step-kind="bill_payments_result"', html)
        self.assertFalse(detail_fixture.Sections(html).folded['payment-progress'])

    def test_multiple_statuses_do_not_become_the_last_status_or_global_paid(self):
        rows = payment_fixture.scenario()
        rows.append(payment_fixture.correlation(70, 'fee-result', 'PaymentKey-Status',
                    dict(PaymentKey=payment_fixture.FEE, Status='Failed'), session='N/A'))
        self.publish(rows)
        detail = self.detail('inquiry')
        card = next(p for p in detail['payment_cards'] if p['kind'] == 'inquiry_payments')
        self.assertEqual(card['status'], 'mixed')
        self.assertEqual(card['status_values'], ['Failed', 'Success'])
        reports = [s for s in detail['steps'] if s['kind'] == 'inquiry_payments_result']
        self.assertEqual({s['code'] for s in reports}, {'Success', 'Failed'})

    def test_late_na_payment_updates_same_execution_without_advancing_cursor(self):
        self.publish(payment_fixture.scenario(status=None))
        before = self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns']
        key = self.db.lookup_request('inquiry')['request_key']
        anchor = self.db.one('SELECT anchor_key FROM viewer_semantic_occurrences WHERE request_key=?', (key,))['anchor_key']
        detail = self.detail('inquiry')
        self.assertEqual(next(p for p in detail['payment_cards'] if p['kind'] == 'bill_payments')['status'], 'unknown')
        self.publish([payment_fixture.correlation(85, 'bill-result', 'PaymentKey-Status',
                      dict(PaymentKey=payment_fixture.PAY, Status='Success'), session='N/A')], mode='manual_recheck')
        detail = self.detail('inquiry')
        self.assertEqual(next(p for p in detail['payment_cards'] if p['kind'] == 'bill_payments')['status'], 'success')
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'], before)
        self.assertEqual(self.db.one('SELECT anchor_key FROM viewer_semantic_occurrences WHERE request_key=?', (key,))['anchor_key'], anchor)

    def test_registering_an_invoice_is_visible_but_does_not_manufacture_payment(self):
        rows = self.postal()
        rows.append(self.row('postal', 'DBPath.pishkhan24.application.ud_prc_invoiceRegister',
                             '(Command Text: ud_prc_invoiceRegister)(Code: 1)(Result: Ok)(SQL Parameters: @invoiceUniqueID=' + 'F' * 32 + ')'))
        self.publish(rows)
        detail = self.detail('postal')
        self.assertTrue(any(s['kind'] == 'invoice_register' for s in detail['steps']))
        self.assertEqual(detail['payment_cards'], [])
        self.assertEqual(detail['result_codes'], ['G00000'])

    def test_partial_payment_view_cannot_claim_an_unqualified_success(self):
        self.publish(payment_fixture.scenario())
        card = self.db.lookup_request('inquiry')
        card['service_payments']['truncated'] = True
        detail = execution_detail(self.db, card)
        self.assertTrue(detail['incomplete'])
        self.assertTrue(all(p['status'] == 'unknown' for p in detail['payment_cards']))

    def test_payment_without_an_invoice_keeps_its_status_and_unresolved_source(self):
        self.publish([payment_fixture.correlation(80, 'callback', 'PaymentKey-Status',
                     dict(PaymentKey=payment_fixture.PAY, Status='Success'), session='N/A')])
        detail = self.detail('callback')
        self.assertEqual(detail['payment_cards'][0]['kind'], 'unresolved_payment')
        self.assertEqual(detail['payment_cards'][0]['status'], 'success')
        self.assertIsNone(detail['payment_cards'][0]['invoice'])
        self.assertEqual(detail['steps'][0]['kind'], 'unresolved_payment_result')

    def test_reviewed_widget_role_remains_an_explicit_operator_choice(self):
        self.publish([self.row('widget', 'Core.v1/UserWidgetsSetDefault Line:1', 'POST (G00000 | successful)')])
        self.db.update_service_role('Core.v1/UserWidgetsSetDefault', 'user_management', 'unknown', 'explicit owner choice')
        self.db.sql("UPDATE viewer_service_catalog_state SET fingerprint='previous'")
        self.db.conn.commit()
        self.db.sync_service_catalog()
        role = self.db.one("SELECT role,reviewed FROM viewer_service_roles WHERE service_path='Core.v1/UserWidgetsSetDefault'")
        self.assertEqual(role, dict(role='user_management', reviewed=1))

    def test_iran_time_uses_the_offset_and_never_guesses_a_naive_timezone(self):
        self.assertEqual(tehran_time('2026-10-31T05:05:00Z'), '2026-10-31 08:35:00')
        self.assertEqual(tehran_time('2026-10-31T08:35:00+03:30'), '2026-10-31 08:35:00')
        self.assertEqual(tehran_time('2026-10-31T08:35:00'), 'زمان بدون منطقهٔ زمانی')
        self.assertEqual(tehran_time(None), '—')

    def test_history_and_live_labels_are_tehran_while_raw_evidence_is_unchanged(self):
        self.publish(self.postal())
        resume_recent(self.db, now=START + 8 * FIVE_NS + 60 * SECOND_NS)
        client = create_viewer_app(self.opts).test_client()
        html = client.get('/').get_data(as_text=True)
        self.assertIn('بازه‌های پردازش‌نشده (تهران)', html)
        self.assertNotIn('</b> UTC', html)
        event = self.db.one('SELECT origin_key,version_key FROM viewer_events LIMIT 1')
        raw = self.db.get_raw(event['origin_key'], event['version_key'])
        page = client.get('/evidence/' + event['origin_key'] + '/' + event['version_key']).get_data(as_text=True)
        self.assertIn('زمان رخداد در تهران', page)
        self.assertIn(raw['@timestamp'], page)

    def test_widget_catalog_upgrade_withdraws_legacy_occurrence_and_preserves_other_reviews(self):
        self.publish(self.postal() + [self.row('widget', 'Core.v1/UserWidgetsSetDefault Line:1', 'POST (G00000 | successful)')])
        widget = 'Core.v1/UserWidgetsSetDefault'
        key = self.db.lookup_request('widget')['request_key']
        self.db.sql("UPDATE viewer_service_roles SET role='user_management',source='source_backed',reviewed=0 WHERE service_path=?", (widget,))
        self.db.sql("UPDATE viewer_actions SET category='user_management' WHERE action_key=?", (key,))
        self.db.sql("UPDATE viewer_service_catalog_state SET fingerprint='previous'")
        self.db.conn.commit()
        self.db.build_semantic_index()
        key = self.db.lookup_request('widget')['request_key']
        self.assertEqual(self.db.one('SELECT state FROM viewer_semantic_occurrences WHERE request_key=?', (key,))['state'], 'active')
        self.db.update_service_role('Services.v1/PostPackagesStatus', 'business', 'unknown', 'owner keeps this service')
        reviewed = self.db.one("SELECT * FROM viewer_service_roles WHERE service_path='Services.v1/PostPackagesStatus'")
        raw = self.db.all('SELECT * FROM viewer_raw_events ORDER BY origin_key,version_key')
        before = self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns']
        result = self.db.sync_service_catalog()
        self.assertEqual(result['status'], 'UPDATED')
        self.assertEqual(initial_service_role(widget)[:2], ('support', 'unknown'))
        key = self.db.lookup_request('widget')['request_key']
        state = self.db.one('SELECT state FROM viewer_semantic_occurrences WHERE request_key=?', (key,))
        self.assertTrue(state is None or state['state'] == 'withdrawn')
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'], before)
        self.assertEqual(raw, self.db.all('SELECT * FROM viewer_raw_events ORDER BY origin_key,version_key'))
        self.assertEqual(reviewed, self.db.one("SELECT * FROM viewer_service_roles WHERE service_path='Services.v1/PostPackagesStatus'"))


if __name__ == '__main__':
    unittest.main()
