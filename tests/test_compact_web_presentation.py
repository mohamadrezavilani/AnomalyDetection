import unittest
from unittest.mock import patch, MagicMock
from compact_product.web import create_app
from compact_product.config import Config
from compact_ad import MODEL
from compact_behavior import FEATURES


class PresentationTests(unittest.TestCase):
    def setUp(self):
        self.store = patch('compact_product.web.Store').start()
        self.addCleanup(patch.stopall)
        self.db = self.store.return_value.conn
        self.app = create_app(Config(), {}, 'stream', secret='test')
        self.client = self.app.test_client()

    def test_group_list_labels_threshold_and_keeps_identity_inside_details(self):
        self.db.execute.return_value.fetchall.return_value = [dict(
            group_id='a'*32, methods=['actor_rate'], service='Core.v1/LoginByOTP',
            session_id='private-long-session',session_count=2,has_service_scope=True,first_ns=0,last_ns=300000000000,
            signal_count=3,finding_id='f',result=dict(observed=51,baseline=3,
            threshold=18.8,reference_windows=24))]
        response=self.client.get('/incidents')
        self.assertEqual(response.status_code,200)
        body=response.get_data(as_text=True)
        self.assertIn('آستانهٔ تشخیص',body)
        self.assertIn('3 هشدار مرتبط',body)
        self.assertIn('/incident-groups/'+'a'*32,body)
        self.assertNotIn('>private-long-session<',body)
        sql,args=self.db.execute.call_args.args
        self.assertIn('GROUP BY',sql)
        self.assertIn('timing_confirmed_revision=r.revision',sql)
        self.assertIn('source_published_ns=w.published_at_ns',sql)
        self.assertIn('processed_version<d.version',sql)
        self.assertIn('processed_version<j.version',sql)
        self.assertIn('finding_revision=f.revision',sql)
        self.assertEqual(args[:5],['stream',MODEL,FEATURES,MODEL,FEATURES])

    def test_bad_group_and_cursor_are_rejected(self):
        self.assertEqual(self.client.get('/incident-groups/nope').status_code,404)
        self.assertEqual(self.client.get('/incidents?before=nope&id=a').status_code,400)

    def test_empty_group_does_not_claim_no_anomaly(self):
        self.db.execute.return_value.fetchall.return_value=[]
        r=self.client.get('/incident-groups/'+'a'*32)
        self.assertEqual(r.status_code,200)
        self.assertIn('بازتحلیل',r.get_data(as_text=True))


class SearchContractTests(unittest.TestCase):
    def test_exact_ids_and_tehran_bounds_are_parameterized(self):
        from compact_product.search import filters
        from compact_behavior.extract import behavior_id,instant
        raw='AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'
        values,sql,args=filters({'request_id':raw,'session_id':raw,'ip':'::ffff:192.0.2.10',
            'from':'2026-11-22T11:00','to':'2026-11-22T12:00'},'test')
        self.assertEqual(args[:2],[behavior_id('test',raw),'aaaaaaaabbbbccccddddeeeeeeeeeeee'])
        self.assertNotIn(raw,sql);self.assertNotIn('192.0.2.10',sql)
        self.assertEqual(values['ip'],'192.0.2.10')
        self.assertEqual(args[-2:],[instant('2026-11-22T07:30:00Z'),instant('2026-11-22T08:30:00Z')])

    def test_filter_validation_and_source_spelling_are_not_guessed(self):
        from compact_product.search import filters,decorate
        for args in ({'ip':'not-an-ip'},{'from':'2026-13-01T00:00'},
            {'from':'2026-11-22T12:00','to':'2026-11-22T11:00'},{'request_id':'x'*513}):
            with self.assertRaises(ValueError):filters(args,'t')
        row={'request_id':'aaaaaaaabbbbccccddddeeeeeeeeeeee','session_id':None}
        decorate(row,{'raw_request_ids':['AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE','another-request']})
        self.assertEqual(row['original_request_ids'],['AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'])
        decorate(row,{})
        self.assertEqual(row['original_request_ids'],[])
