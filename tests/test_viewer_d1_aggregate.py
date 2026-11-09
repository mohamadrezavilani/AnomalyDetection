"""Targeted D1 SQL and cross-request global-conflict equivalence."""
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB,token


class D1AggregateTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.keys=self.root/'keys.json';generate_keys(self.keys)
        self.db=ViewerDB(sqlite_path=self.root/'viewer.db',keys_path=self.keys)
        self.addCleanup(self.db.close)
        self.db.init()

    def add(self,name,start,rows):
        path=self.root/name
        with gzip.open(path,'wt',encoding='utf-8') as file:
            json.dump(dict(window_start=start,window_end={
                '2026-10-24T04:15:00Z':'2026-10-24T04:20:00Z',
                '2026-10-24T04:20:00Z':'2026-10-24T04:25:00Z'}[start],
                count=len(rows),logs=rows),file)
        self.assertEqual(self.db.ingest([path])[0]['status'],'IMPORTED')

    def row(self,doc,req,session,callpath,stamp,code='G00000'):
        return {'_source_id':'p24-d1:'+doc,'@timestamp':stamp,'RequestID':req,
                'Session':session,'IP':'192.0.2.9','CallPath':callpath,
                'message':'POST ('+code+' | test)'}

    def test_scoped_origin_index_fence_matches_legacy_even_with_cross_request_version(self):
        r1='11111111-1111-4111-8111-111111111111'
        r2='22222222-2222-4222-8222-222222222222'
        session='abcdef0123456789abcdef0123456789'
        first='2026-10-24T04:15:00Z';second='2026-10-24T04:20:00Z'
        self.add('a.gz',first,[
            self.row('shared',r1,session,'Services.v1/ElectricBills Line:10','2026-10-24T04:15:10Z'),
            self.row('clean',r1,session,'DBPath.x.test Line:11','2026-10-24T04:15:11Z')])
        self.add('b.gz',second,[
            self.row('shared',r2,session,'Services.v1/GasBills Line:12','2026-10-24T04:20:10Z')])
        key=token(self.db.keys,'request',r1)
        self.db.rebuild(request_keys=[key])
        base=self.db._request_aggregate_sql('viewer_events',scoped=True)
        fenced=self.db._request_aggregate_sql('viewer_projection_events',scoped=True,indexed_conflict=True)
        self.assertIn('COUNT(*)',fenced)
        self.assertNotIn('viewer_projection_scope',fenced)
        self.assertIn('viewer_projection_scope',base)
        def execute(query):
            self.db.sql('SAVEPOINT d1_compare')
            try:
                self.db.sql('DELETE FROM viewer_requests WHERE request_key=?',(key,))
                self.db.sql(query)
                record=self.db.one('SELECT * FROM viewer_requests WHERE request_key=?',(key,))
                return {k:v for k,v in record.items() if k!='request_key'}
            finally:
                self.db.sql('ROLLBACK TO SAVEPOINT d1_compare')
                self.db.sql('RELEASE SAVEPOINT d1_compare')
        legacy=execute(base);candidate=execute(fenced)
        self.assertEqual(candidate,legacy)
        self.assertEqual(candidate['event_count'],1)
        self.assertEqual(candidate['root_count'],0)
        self.assertEqual(candidate['identity_state'],'assigned')
        # Exercise the new conflict invalidation predicate against the actual
        # retained global versions, including the other RequestID.
        old=self.db.all('SELECT DISTINCT e.request_key FROM viewer_events e WHERE '+
                        self.db._global_conflict_predicate(False)+' ORDER BY e.request_key')
        new=self.db.all('SELECT DISTINCT e.request_key FROM viewer_events e WHERE '+
                        self.db._global_conflict_predicate(True)+' ORDER BY e.request_key')
        self.assertEqual(old,new)
        self.assertEqual({r['request_key'] for r in new},
                         {token(self.db.keys,'request',r1),token(self.db.keys,'request',r2)})

    def test_plan_summarizer_emits_only_bounded_nodes(self):
        plan=[dict(Plan={'Node Type':'Insert','Plan Rows':10,'Total Cost':20.0,
            'Plans':[{'Node Type':'Index Scan','Index Name':'viewer_events_pkey',
                      'Relation Name':'viewer_events','Plan Rows':1,'Total Cost':4.0}]})]
        with patch.object(self.db,'one',return_value={'QUERY PLAN':plan}), patch.object(self.db,'progress') as emit:
            self.db._aggregate_plan('INSERT INTO viewer_requests SELECT ...','bounded_origin_index')
        recorded=emit.call_args
        self.assertEqual(recorded.args,('rebuild_aggregate_plan',))
        self.assertEqual(recorded.kwargs['nodes'][1]['index'],'viewer_events_pkey')
        self.assertNotIn('sql',json.dumps(recorded.kwargs).lower())

    def test_bounded_root_selection_equals_legacy_with_cross_scope_conflict_and_late_root(self):
        first='2026-10-24T04:15:00Z';second='2026-10-24T04:20:00Z'
        session='a'*32;r1='1'*32;r2='2'*32;r3='3'*32
        self.add('roots-a.gz',first,[
            self.row('shared-root',r1,session,'Services.v1/GasBills Line:1','2026-10-24T04:15:10Z'),
            self.row('clean-old',r1,session,'Services.v1/WaterBills Line:1','2026-10-24T04:15:11Z'),
            self.row('auto',r3,session,'Core.v1/InvoiceRegister Line:4','2026-10-24T04:15:12Z')])
        self.add('roots-b.gz',second,[
            self.row('shared-root',r2,session,'Services.v1/GasBills Line:1','2026-10-24T04:20:20Z','GD2016'),
            self.row('clean-new',r1,session,'Services.v1/WaterBills Line:1','2026-10-24T04:20:21Z')])
        keys=[token(self.db.keys,'request',r) for r in (r1,r3)]
        self.db.rebuild(request_keys=keys)
        params=('%/InvoiceRegister %','Webhook.%','PaymentCallback.%','JobsQueue.%')
        def run(indexed):
            self.db.sql('SAVEPOINT compare_roots')
            try:
                self.db.sql("UPDATE viewer_requests SET root_call=NULL,root_code=NULL,root_ns=NULL,initiation='unknown'")
                self.db.sql(self.db._request_roots_sql('viewer_projection_events',scoped=True,
                                                     indexed_conflict=indexed),params)
                return self.db.all('SELECT request_key,root_call,root_code,root_ns,initiation FROM viewer_requests ORDER BY request_key')
            finally:
                self.db.sql('ROLLBACK TO SAVEPOINT compare_roots');self.db.sql('RELEASE SAVEPOINT compare_roots')
        legacy=run(False);bounded=run(True)
        self.assertEqual(legacy,bounded)
        root=next(r for r in bounded if r['request_key']==keys[0])
        self.assertEqual(root['root_call'],'Services.v1/WaterBills Line:1')
        self.assertEqual(root['root_code'],'G00000')
        self.assertEqual(next(r for r in bounded if r['request_key']==keys[1])['initiation'],'confirmed_automatic')

    def test_batched_conflict_evidence_matches_legacy_with_compatible_and_contradictory_roots(self):
        first='2026-10-24T04:15:00Z';second='2026-10-24T04:20:00Z';session='a'*32
        rows=[]
        for doc,rid,call,code in (
            ('ok1','compatible','Services.v1/WaterBills Line:1','G00000'),
            ('ok2','compatible','Services.v1/WaterBills Line:99','G00000'),
            ('path1','path-conflict','Services.v1/WaterBills Line:1','G00000'),
            ('path2','path-conflict','Services.v1/GasBills Line:1','G00000'),
            ('code1','code-conflict','Services.v1/WaterBills Line:1','G00000'),
            ('code2','code-conflict','Services.v1/WaterBills Line:1','GD2016'),
            ('shared','outside-version','Services.v1/GasBills Line:1','G00000'),
            ('valid1','outside-version','Services.v1/WaterBills Line:1','G00000'),
            ('valid2','outside-version','Services.v1/WaterBills Line:2','G00000')):
            rows.append(self.row(doc,rid,session,call,'2026-10-24T04:15:10Z',code))
        self.add('conflicts-a.gz',first,rows)
        self.add('conflicts-b.gz',second,[self.row('shared','other-request',session,
                 'Services.v1/GasBills Line:1','2026-10-24T04:20:10Z','GD2016')])
        keys=[token(self.db.keys,'request',rid) for rid in
              ('compatible','path-conflict','code-conflict','outside-version')]
        self.db.rebuild(request_keys=keys)
        legacy={}
        for r in self.db.all('SELECT request_key FROM viewer_requests WHERE root_count>1'):
            legacy[r['request_key']]={(v['callpath'].split(' Line:')[0],v['code']) for v in self.db.all(
                """SELECT e.callpath,e.code FROM viewer_projection_events e WHERE e.request_key=?
                   AND e.kind='client' AND NOT EXISTS(SELECT 1 FROM viewer_events bad
                     WHERE bad.origin_key=e.origin_key AND bad.version_key<>e.version_key)""",(r['request_key'],))}
        for indexed in (False,True):
            actual={}
            for r in self.db.all(self.db._request_conflict_evidence_sql('viewer_projection_events',indexed=indexed)):
                actual.setdefault(r['request_key'],set()).add((r['callpath'].split(' Line:')[0],r['code']))
            self.assertEqual(actual,legacy)
        for rid in ('compatible','outside-version'):
            # The globally conflicted origin is fenced from root selection;
            # the request itself still honestly reports that origin conflict.
            key=token(self.db.keys,'request',rid)
            self.assertEqual(len(legacy[key]),1)
        for rid in ('path-conflict','code-conflict'):
            r=self.db.lookup_request(rid)
            self.assertEqual(r['conflicted'],1);self.assertIsNone(r['root_call'])

    def test_access_session_fence_matches_join_and_preserves_global_conflicts(self):
        first='2026-10-24T04:15:00Z';second='2026-10-24T04:20:00Z';session='a'*32
        rows=[self.row(doc,rid,ss,'Services.v1/WaterBills Line:1','2026-10-24T04:15:10Z')
              for doc,rid,ss in [('mismatch','mismatch',session),('matching','matching',session),
                                 ('shared','global-conflict',session),('missing','missing','N/A')]]
        self.add('access-a.gz',first,rows)
        self.add('access-b.gz',second,[self.row('shared','outside',session,
                 'Services.v1/GasBills Line:1','2026-10-24T04:20:10Z')])
        for e in self.db.all('SELECT * FROM viewer_events WHERE request_key<>?',
                             (token(self.db.keys,'request','outside'),)):
            matches=e['request_key']==token(self.db.keys,'request','matching')
            self.db.sql('INSERT INTO viewer_links VALUES(?,?,?,?,?)',
                (e['origin_key'],e['version_key'],e['request_key'],'access_session',
                 e['session_key'] if matches else token(self.db.keys,'session','b'*32)))
        keys=[token(self.db.keys,'request',rid) for rid in ('mismatch','matching','global-conflict','missing')]
        self.db.rebuild(request_keys=keys)
        legacy="""UPDATE viewer_requests SET identity_state='conflicting',conflicted=1,session_key=NULL
          WHERE request_key IN (SELECT e.request_key FROM viewer_projection_events e JOIN viewer_links l
            ON l.origin_key=e.origin_key AND l.version_key=e.version_key
            WHERE l.link_domain='access_session' AND e.session_key IS NOT NULL AND l.link_key<>e.session_key
              AND NOT EXISTS(SELECT 1 FROM viewer_events bad WHERE bad.origin_key=e.origin_key
                             AND bad.version_key<>e.version_key))
          AND request_key IN (SELECT request_key FROM viewer_projection_scope)"""
        def execute(sql):
            self.db.sql('SAVEPOINT compare_access')
            try:
                self.db.sql("UPDATE viewer_requests SET conflicted=0,identity_state='assigned',session_key='baseline'")
                self.db.sql(sql)
                return self.db.all('SELECT request_key,conflicted,identity_state,session_key FROM viewer_requests ORDER BY request_key')
            finally:
                self.db.sql('ROLLBACK TO SAVEPOINT compare_access');self.db.sql('RELEASE SAVEPOINT compare_access')
        expected=execute(legacy)
        for indexed in (False,True):
            self.assertEqual(execute(self.db._access_session_conflicts_sql(
                'viewer_projection_events',scoped=True,indexed=indexed)),expected)
        self.assertEqual({r['request_key'] for r in expected if r['conflicted']},
                         {token(self.db.keys,'request','mismatch')})

    def test_incremental_payment_index_has_bounded_request_and_global_origin_probes(self):
        query=self.db._projection_payment_links_sql(scoped=True,postgres=True)
        self.assertIn('CROSS JOIN LATERAL',query)
        self.assertIn('source.request_key=s.request_key',query)
        self.assertIn('OFFSET 0',query)
        self.assertIn('bad.origin_key=l.origin_key AND bad.version_key<>l.version_key)=0',query)
        self.assertNotIn('NOT EXISTS',query)

if __name__=='__main__':unittest.main()
