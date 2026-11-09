"""Bill item provenance and reverse navigation; isolated synthetic evidence."""
import gzip
import json
import unittest

from tests import test_viewer_inquiry_journey as fixture
from tests.test_viewer_inquiry_journey import (record,
    cache_add, cache_get, NEW_ITEM, OLD_ITEM, EXTRA_ITEM)


class BillItemNavigationTests(unittest.TestCase):
    setUp=fixture.InquiryPaymentJourneyTest.setUp
    prepare=fixture.InquiryPaymentJourneyTest.prepare
    def key(self, raw):
        return self.db.lookup_request(raw)['request_key']

    def add(self, rows):
        path=self.gz.with_name('addition'+str(len(list(self.gz.parent.glob('addition*'))))+'.gz')
        with gzip.open(path,'wt',encoding='utf-8') as f:
            json.dump(dict(window_start='2026-10-24T04:00:00Z',window_end='2026-10-24T04:05:00Z',count=len(rows),logs=rows),f)
        self.db.ingest([path]);self.db.rebuild();self.db.rebuild_payment_contract()

    def test_three_entry_points_preserve_same_distinct_requests(self):
        self.prepare()
        expected={self.key(x) for x in ('new','basket','payment')}
        for raw in ('new','basket','payment'):
            journey=self.db.lookup_request(raw)['bill_item_journey']
            got={r['request_key'] for k in ('inquiries','basket_additions','payment_attempts') for r in journey[k]}
            self.assertEqual(got,expected)
            self.assertFalse(journey['truncated'])
            self.assertEqual(journey['financial_confirmation'],'unverified')
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_requests')['n'],4)

    def test_explicit_selection_points_to_sql_even_with_cache_reference(self):
        self.prepare()
        self.add([record(15,3,'basket','CacheCoreApi.HandleRequest Line:56',cache_get(NEW_ITEM))])
        step=self.db.lookup_request('new')['bill_item_journey']['basket_additions'][0]
        self.assertEqual(step['relation'],'explicit_item_selection')
        self.assertIn('ud_prc_billsBelongs',step['evidence']['callpath'])
        self.assertIn('@bills',step['evidence']['field_path'])
        self.assertIn('UniqueID',step['inquiry_evidence']['field_path'])

    def test_unrelated_item_cannot_bridge_through_multi_item_inquiry(self):
        self.prepare()
        self.add([record(20,2,'new','CacheCoreApi.HandleRequest Line:56',cache_add(EXTRA_ITEM)),
            record(21,4,'other-basket','DBPath.x.ud_prc_billsBelongs',
                '(Command Text: ud_prc_billsBelongs)(SQL Parameters: @bills='+EXTRA_ITEM+')'),
            record(22,4,'other-basket','Core.v1/UserBasketAddBills Line:4','POST (G00000 | successful)')])
        j=self.db.lookup_request('basket')['bill_item_journey']
        self.assertEqual({r['request_key'] for r in j['basket_additions']},{self.key('basket')})
        step=j['payment_attempts'][0]
        self.assertEqual(step['linked_items'],1)
        self.assertEqual([x['item_id'] for x in step['item_evidence']],[NEW_ITEM])

    def test_bounds_are_explicit_and_do_not_claim_global_absence(self):
        self.prepare();self.db._bill_journey_page_limit=1
        j=self.db.lookup_request('payment')['bill_item_journey']
        self.assertTrue(j['truncated'])
        self.assertEqual(j['scope'],'bounded_session_request_neighborhood_not_full_history')

    def test_reused_reader_observes_late_item_evidence(self):
        self.prepare()
        old=self.db.lookup_request('old')['bill_item_journey']
        self.assertEqual(old['basket_additions'],[])
        self.add([record(25,3,'late-basket','DBPath.x.ud_prc_billsBelongs',
            '(Command Text: ud_prc_billsBelongs)(SQL Parameters: @bills='+OLD_ITEM+')'),
            record(26,3,'late-basket','Core.v1/UserBasketAddBills Line:3','POST (G00000 | successful)')])
        new=self.db.lookup_request('old')['bill_item_journey']
        self.assertEqual({r['request_key'] for r in new['basket_additions']},{self.key('late-basket')})

    def test_cross_request_origin_conflict_blocks_links(self):
        self.prepare()
        changed=record(3,2,'competing-request','CacheCoreApi.HandleRequest Line:56',cache_add(NEW_ITEM))
        self.add([changed])
        j=self.db.lookup_request('new')['bill_item_journey']
        self.assertEqual(j['status'],'unresolved')
        self.assertEqual(j['basket_additions'],[])

    def test_empty_shared_basket_reference_is_not_a_bill_item_link(self):
        self.prepare()
        self.add([record(30,3,'context-only','DBPath.x.ud_prc_basketAddItems',
            '(Command Text: ud_prc_basketAddItems)(SQL Parameters: @basketID=42)'),
            record(31,3,'context-only','Core.v1/UserBasketAddBills Line:3','POST (G00000 | successful)')])
        j=self.db.lookup_request('context-only')['bill_item_journey']
        self.assertEqual(j['status'],'unresolved')
        self.assertEqual(j['inquiries'],[])

    def test_multi_item_row_keeps_selection_scope_and_both_inquiry_proofs(self):
        self.prepare()
        self.add([record(40,2,'extra-inquiry','CacheCoreApi.HandleRequest Line:56',cache_add(EXTRA_ITEM)),
            record(41,2,'extra-inquiry','Services.v1/CellPhoneBills Line:1','POST (G00000 | successful)'),
            record(42,3,'basket','CacheCoreApi.HandleRequest Line:56',cache_get(NEW_ITEM,EXTRA_ITEM))])
        journey=self.db.lookup_request('basket')['bill_item_journey']
        self.assertEqual({x['request_key'] for x in journey['inquiries']},{self.key('new'),self.key('extra-inquiry')})
        step=journey['basket_additions'][0]
        self.assertEqual(step['linked_items'],2)
        self.assertEqual(step['explicit_selection_item_count'],1)
        kinds={x['item_id']:x['relation'] for x in step['item_evidence']}
        self.assertEqual(kinds[NEW_ITEM],'explicit_item_selection')
        self.assertEqual(kinds[EXTRA_ITEM],'referenced_snapshot_item')
        self.assertIn('ud_prc_billsBelongs',step['evidence']['callpath'])
