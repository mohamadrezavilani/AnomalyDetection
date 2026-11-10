"""Dependency traversal, scoped evidence reuse and top-one session-head parity."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB, token
from p24_foundation.viewer_online import affected_closure, initialize_live, bind_stream, publish_capture
from tests.test_viewer_online import START, FIVE_NS, verified_file, snapshot, iso
from tests.test_viewer_r6_service_journey import log, sql


def legacy_closure(db, keys, limit=250000):
    found=set(keys);front=set(keys)
    while front:
        new=set();ordered=sorted(front)
        for begin in range(0,len(ordered),500):
            batch=ordered[begin:begin+500]
            new.update(row['request_key'] for row in db.all('''SELECT DISTINCT b.request_key
                FROM viewer_links a JOIN viewer_links b ON a.link_domain=b.link_domain AND a.link_key=b.link_key
                WHERE a.link_domain='platform_payment' AND a.request_key IN ('''+','.join('?' for _ in batch)+''')
                AND b.request_key IS NOT NULL''',batch))
        front=new-found;found.update(front)
        if len(found)>limit:raise ValueError('affected_dependency_budget_exceeded')
    return sorted(found)


class MinimalPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);generate_keys(self.root/'keys')
        self.db=ViewerDB(sqlite_path=self.root/'viewer',keys_path=self.root/'keys')
        self.addCleanup(self.db.close);self.db.init();initialize_live(self.db)
        bind_stream(self.db,start_ns=START,stream_key='minimal-publication')

    def link(self, request, group, index, domain='platform_payment'):
        self.db.sql('INSERT INTO viewer_links VALUES(?,?,?,?,?)',
            ('origin'+str(index),'version',request,domain,group))

    def test_payment_hyperedges_cycles_bridges_nulls_and_conflicting_old_links_match(self):
        for index,(request,group) in enumerate((('a','one'),('b','one'),('b','two'),('c','two'),
                ('c','three'),('a','three'),('c','old-conflicting-group'),('d','old-conflicting-group'),
                ('unrelated','separate'),(None,'one'))):
            self.link(request,group,index)
        self.link('wrong-domain','one',20,domain='invoice')
        calls=[];original=self.db.all
        def trace(query,params=()):
            calls.append((query,params));return original(query,params)
        expected=legacy_closure(self.db,['a'])
        with patch.object(self.db,'all',side_effect=trace):
            self.assertEqual(affected_closure(self.db,['a']),expected)
        self.assertEqual(expected,['a','b','c','d'])
        expanded=[value for query,params in calls if 'link_key IN (' in query for value in params[:-1]]
        self.assertEqual(len(expanded),len(set(expanded)))
        self.assertEqual(set(expanded),{'one','two','three','old-conflicting-group'})
        self.assertTrue(all('JOIN viewer_links' not in query for query,_ in calls))

    def test_large_shared_group_is_expanded_once_across_multiple_request_batches(self):
        keys=['r'+str(n).zfill(4) for n in range(1201)]
        for n,key in enumerate(keys):self.link(key,'shared',n)
        self.link('outside','other',5000)
        calls=[];original=self.db.all
        def trace(query,params=()):calls.append((query,params));return original(query,params)
        with patch.object(self.db,'all',side_effect=trace):
            self.assertEqual(affected_closure(self.db,keys[:1000]),keys)
        expanded=[query for query,_ in calls if 'link_key IN (' in query]
        self.assertEqual(len(expanded),1)
        with self.assertRaisesRegex(ValueError,'affected_dependency_budget_exceeded'):
            affected_closure(self.db,[keys[0]],limit=1200)
        with self.assertRaisesRegex(ValueError,'affected_dependency_budget_exceeded'):
            affected_closure(self.db,keys,limit=1200)

    def test_new_bridge_in_later_publication_is_not_hidden_by_a_persistent_cache(self):
        self.link('a','one',1);self.link('b','one',2)
        self.assertEqual(affected_closure(self.db,['a']),['a','b'])
        self.link('b','two',3);self.link('c','two',4)
        self.assertEqual(affected_closure(self.db,['a']),['a','b','c'])

    def test_contract_reuses_only_atomic_scoped_events_and_keeps_global_conflict_checks(self):
        for options in ({'reuse_projection_events':True},
                {'reuse_projection_events':True,'request_keys':[],'commit':True}):
            with self.assertRaisesRegex(ValueError,'contract_event_reuse'):
                self.db.rebuild_payment_contract(**options)
        native=object.__new__(ViewerDB);native.sqlite=False
        query=native._contract_read_query(scoped=True,payload=False,reuse_projection_events=True)
        self.assertIn('FROM viewer_projection_events e',query)
        self.assertIn('FROM viewer_projection_versions v',query)
        self.assertIn('SELECT COUNT(*) FROM viewer_raw_events b',query)
        self.assertNotIn('FROM viewer_events e',query)
        self.assertIn('CROSS JOIN LATERAL',native._contract_read_query(scoped=True,payload=False))
        self.assertIn('OFFSET 0',native._contract_read_query(scoped=True,payload=False))

    def test_atomic_reused_events_match_previous_contract_reader_and_preserve_transitions(self):
        old=ViewerDB(sqlite_path=self.root/'old',keys_path=self.root/'keys');self.addCleanup(old.close)
        old.init();initialize_live(old);bind_stream(old,start_ns=START,stream_key='minimal-publication')
        original=old._contract_read_query
        old._contract_read_query=lambda **kw:original(**dict(kw,reuse_projection_events=False))
        first=[log(1,'pay','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K')),
            log(2,'pay','Core.v1/WalletPayment Line:1','POST (G00000 | successful)'),
            log(3,'late','ClientAyanCoTopUp.ProductReserve Line:1','Output:[]')]
        late=log(4,'late','Services.v1/TopUpProductPurchase Line:1','POST (G00000 | successful)')
        late['@timestamp']=iso(START+FIVE_NS+1_000_000_000)
        callback=log(5,'callback','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K'))
        callback['@timestamp']=iso(START+FIVE_NS+2_000_000_000)
        changed=copy.deepcopy(first[0]);changed['RequestID']='new-owner';changed['message']=sql('ud_prc_paymentExists',paymentKey='K2')
        for index,(rows,start,mode) in enumerate(((first,START,'forward'),([late,callback],START+FIVE_NS,'forward'),
                ([changed,*first[1:]],START,'recheck'))):
            path=verified_file(self.root/('capture'+str(index)+'.gz'),rows,start)
            for db in (old,self.db):publish_capture(db,path,start,start+FIVE_NS,mode=mode)
            self.assertEqual(snapshot(old),snapshot(self.db))
            columns='request_key,revision,old_kind,new_kind,old_occurrence_key,new_occurrence_key,transition'
            self.assertEqual(old.all('SELECT '+columns+' FROM viewer_semantic_transitions ORDER BY request_key,revision'),
                self.db.all('SELECT '+columns+' FROM viewer_semantic_transitions ORDER BY request_key,revision'))
        self.assertEqual(self.db.lookup_request('pay')['conflicted'],1)
        self.assertEqual(self.db.lookup_request('new-owner')['conflicted'],1)

    def test_top_one_head_matches_full_ranking_including_ties_withdrawals_and_unrelated_session(self):
        rows=[]
        for n in range(5000):
            request=str(n).zfill(64)
            rows.append((request,'anchor'+request,'hot' if n<4998 else 'other',n//2,
                'service_execution','occ'+request,'active' if n!=4997 else 'withdrawn',1,'fixture'))
        self.db.many('''INSERT INTO viewer_semantic_occurrences(request_key,anchor_key,session_key,anchor_ns,
            kind,occurrence_key,state,revision,updated_at) VALUES(?,?,?,?,?,?,?,?,?)''',rows)
        self.db._refresh_semantic_session_heads()
        before=self.db.all('SELECT * FROM viewer_semantic_session_heads ORDER BY session_key')
        vm=[];self.db.conn.set_progress_handler(lambda:vm.append(1) or 0,1000)
        try:self.db._refresh_semantic_session_heads(['hot'])
        finally:self.db.conn.set_progress_handler(None,0)
        self.assertEqual(before,self.db.all('SELECT * FROM viewer_semantic_session_heads ORDER BY session_key'))
        self.assertLess(len(vm),10,'a one-session head update scanned retained history')
        self.db.sql("UPDATE viewer_semantic_occurrences SET state='withdrawn' WHERE session_key='hot'")
        self.db._refresh_semantic_session_heads(['hot'])
        self.assertEqual(self.db.all('SELECT session_key FROM viewer_semantic_session_heads'),[{'session_key':'other'}])


if __name__=='__main__':unittest.main()
