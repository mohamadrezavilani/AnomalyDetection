"""Independent RequestID index; no actual customer data or PostgreSQL required."""
from __future__ import annotations
import gzip
import json
import tempfile
import unittest
from pathlib import Path
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB,initial_service_role
try:
    from p24_foundation.viewer_ui import create_viewer_app
except ImportError as exc:
    if exc.name != 'flask':
        raise
    create_viewer_app = None
from jinja2 import Environment,FileSystemLoader,StrictUndefined

SESSION1='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
SESSION2='BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
RID1='10000000-0000-4000-8000-000000000001'
RID2='10000000-0000-4000-8000-000000000002'
RID3='10000000-0000-4000-8000-000000000003'
RID4='10000000-0000-4000-8000-000000000004'


def root(n,rid,session,time,path,code='G00000'):
    return {'_source_id':f'idx:{n}','RequestID':rid,'Session':session,
       '@timestamp':time,'CallPath':path,'IP':'192.0.2.11',
       'message':f'POST https://example.test/{path} ({code} | status)'}


class RequestsIndexTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        base=Path(tmp.name)
        self.keys=base/'keys.json';generate_keys(self.keys)
        self.file=base/'logs.json.gz';self.dbfile=base/'model.db'
        rows=[
            root(1,RID1,SESSION1,'2026-10-24T04:00:00Z','Services.v1/ElectricBills Line:10'),
            root(2,RID2,SESSION1,'2026-10-24T06:00:00Z','Services.v1/ElectricBills Line:10'),
            root(3,RID3,SESSION1,'2026-10-24T06:03:00Z','Services.v1/AddUserData Line:10'),
            root(4,RID4,SESSION2,'2026-10-24T06:04:00Z','Services.v2/GasBills Line:50','GD2016'),
        ]
        with gzip.open(self.file,'wt',encoding='utf-8') as f:
            json.dump({'window_start':'2026-10-24T03:30:00Z','window_end':'2026-10-24T06:20:00Z','logs':rows,'count':len(rows)},f)
        self.db=ViewerDB(sqlite_path=self.dbfile,keys_path=self.keys)
        self.addCleanup(self.db.close)
        self.db.init();self.db.ingest([self.file]);self.db.rebuild()

    def test_request_list_is_one_row_per_request_even_same_target(self):
        page=self.db.requests_page(limit=20,offset=0)
        self.assertEqual(page['total'],4)
        self.assertEqual(len({x['request_key'] for x in page['items']}),4)
        page=self.db.requests_page(20,0,session=SESSION1)
        self.assertEqual(page['total'],3)
        self.assertEqual([x['raw_request_id'] for x in self.db.requests_page(20,0,role='business')['items']],
                         [RID4,RID2,RID1])
        self.assertEqual(self.db.requests_page(20,0,request_id=RID1)['total'],1)
        self.assertEqual(self.db.requests_page(20,0,service='electricbills')['total'],2)
        self.assertEqual(self.db.requests_page(20,0,outcome='failure')['total'],1)
        self.assertEqual(self.db.requests_page(20,0,service='Electric%')['total'],0)
        self.assertEqual(self.db.requests_page(20,0,from_ns=(1792814400+1)*10**9)['total'],3)
        paged=self.db.requests_page(1,1)
        self.assertEqual((paged['total'],len(paged['items'])),(4,1))

    def test_service_proposals_do_not_overwrite_operator_unknown(self):
        self.assertEqual(initial_service_role('Services.v2/GasBills')[0],'business')
        self.assertEqual(initial_service_role('Services.v3/UnseenNeverInLogs')[0],'unknown')
        self.db.update_service_role('Services.v2/GasBills','unknown','unknown','operator-reviewed')
        self.db.rebuild()
        self.assertEqual(self.db.requests_page(20,0,role='business')['total'],2)
        self.assertEqual(self.db.requests_page(20,0,role='unknown')['total'],1)
        rec=self.db.one("SELECT * FROM viewer_service_roles WHERE service_path='Services.v2/GasBills'")
        self.assertEqual(rec['source'],'operator')

    def test_postgres_placeholder_protocol_simulated_for_page(self):
        # This is a psycopg-placeholder simulation, NOT a live PG test.
        from tests.test_viewer_install_regressions import StrictPgPercentConnection
        native=self.db.conn
        self.db.conn=StrictPgPercentConnection(native)
        self.db.sqlite=False
        try:
            result=self.db.requests_page(20,0,service='ElectricBills',role='business')
            self.assertEqual(result['total'],2)
            self.assertEqual(self.db.requests_page(10,0,request_id=RID1)['total'],1)
        finally:
            self.db.conn=native
            self.db.sqlite=True

    def test_session_summary_is_bounded(self):
        sessions=self.db.sessions(10,0)
        a=next(r for r in sessions['items'] if r['raw_session_id']==SESSION1)
        self.assertEqual(a['business_count'],2)
        self.assertEqual(a['latest_business'],'ElectricBills')
        self.assertNotIn('services',a)

    @unittest.skipIf(create_viewer_app is None, "Flask not available in offline execution environment")
    def test_real_flask_pages_render_and_keep_filter_pagination(self):
        app=create_viewer_app({'sqlite_path':self.dbfile,'keys_path':self.keys})
        client=app.test_client()
        page=client.get('/requests?service=ElectricBills&limit=1')
        self.assertEqual(page.status_code,200)
        self.assertIn('ElectricBills',page.get_data(as_text=True))
        self.assertIn('page=2',page.get_data(as_text=True))
        self.assertIn('service=ElectricBills',page.get_data(as_text=True))
        self.assertEqual(client.get('/requests?service=ElectricBills&page=2&limit=1').status_code,200)
        self.assertEqual(client.get('/requests?role=bad-value').status_code,400)
        self.assertEqual(client.get('/').status_code,200)
        self.assertEqual(client.get('/requests?role=unknown').status_code,200)
        self.assertNotIn('اقدام‌های اصلی',client.get('/session/'+self.db.lookup_request(RID1)['session_key']).get_data(as_text=True))

    def test_request_template_allows_filter_and_paging_without_flask(self):
        troot=Path(__file__).resolve().parents[1]/'review_ui'/'templates'
        env=Environment(loader=FileSystemLoader(str(troot)),undefined=StrictUndefined,autoescape=True)
        from p24_foundation.viewer_display_time import tehran_time
        env.filters['tehran_time']=tehran_time
        env.globals['url_for']=lambda endpoint,**kwargs:'/requests?page='+str(kwargs.get('page',1))+'&service='+str(kwargs.get('service',''))
        entries=self.db.requests_page(1,0,service='ElectricBills')['items']
        html=env.get_template('viewer_requests.html').render(result={'items':entries,'total':2},page=1,limit=1,
            session='',request_id='',service='ElectricBills',role='',outcome='',start='',end='',internal=False,version='vtest')
        self.assertIn('ElectricBills',html)
        self.assertIn('page=2',html)
        self.assertIn('service=ElectricBills',html)
        self.assertIn('RequestID',html)



if __name__=='__main__':unittest.main()
