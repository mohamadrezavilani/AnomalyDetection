"""v0.2.3 catalogue/navigation regression tests. No live PostgreSQL required.

Offline tests do not prove the Windows Flask/PostgreSQL deployment.
"""
import gzip
import json
import tempfile
import unittest
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB

try:
    from p24_foundation.viewer_ui import create_viewer_app
except ImportError as exc:
    if exc.name != 'flask': raise
    create_viewer_app = None

ROOT=Path(__file__).resolve().parents[1]
S='B'*32
RIDS=['12345678-1234-4234-8234-1234567890%02d'%i for i in range(1,9)]

def log(i,call,session=S):
    return {'@timestamp':'2026-10-24T04:%02d:00Z'%i,'RequestID':RIDS[i-1],
            'Session':session,'IP':'192.0.2.2','CallPath':call,
            'message':'POST https://example.test/endpoint (G00000 | successful)',
            '_source_id':'independent-index:doc-'+str(i)}

class CatalogNavigationTests(unittest.TestCase):
    def setUp(self):
        d=tempfile.TemporaryDirectory();self.addCleanup(d.cleanup)
        base=Path(d.name)
        self.keys=base/'keys.json';generate_keys(self.keys)
        self.dbpath=base/'viewer.db';self.db=ViewerDB(sqlite_path=self.dbpath,keys_path=self.keys)
        self.addCleanup(self.db.close);self.db.init()
        self.data=base/'events.json.gz'
        rows=[
            log(1,'Services.v1/ElectricBills Line:100'),
            log(2,'Services.v1/ElectricBills Line:200'),
            log(3,'Services.v2/ElectricBills Line:100'),
            log(4,'Services.v1/ElectricBillsExtended Line:100'),
            log(5,'Services.v1/GetUserData Line:12'),
            log(6,'Core.v1/UserServiceQueryBookmark Line:21'),
            log(7,'Core.v1/UncatalogedRoute Line:42'),
            log(8,'Webhook.v1/InformBillsPaymentStatus Line:22',session='N/A'),
        ]
        with gzip.open(self.data,'wt',encoding='utf8') as f:
            json.dump({'logs':rows,'count':len(rows),'window_start':'2026-10-24T04:00:00Z','window_end':'2026-10-24T05:00:00Z'},f)
        self.db.ingest([self.data]);self.db.rebuild()

    def test_counts_are_global_even_when_filter_and_page_applied(self):
        all_roles=self.db.service_roles(100)
        self.assertEqual(all_roles['global_total'],8-1) # both line numbers same canonical path
        self.assertEqual(sum(all_roles['role_totals'].values()),all_roles['global_total'])
        self.assertEqual(all_roles['role_totals']['unknown'],3)
        partial=self.db.service_roles(1,0,search='ElectricBills',role='business')
        self.assertEqual(partial['global_total'],all_roles['global_total'])
        self.assertEqual(partial['role_totals'],all_roles['role_totals'])
        self.assertEqual(partial['total'],1)  # only explicit seeded v1; v2 remains unknown
        self.assertEqual(len(partial['items']),1)

    def test_sample_real_request_id_and_exact_full_list(self):
        by_name={x['service_path']:x for x in self.db.service_roles(100)['items']}
        sample=by_name['Services.v1/ElectricBills']
        self.assertEqual(sample['requests'],2)
        self.assertTrue(sample['sample_request_key'])
        self.assertIn(sample['sample_request_id'],RIDS[:2])
        self.assertEqual(self.db.requests_page(25,0,service_path_filter='Services.v1/ElectricBills')['total'],2)
        self.assertEqual(self.db.requests_page(25,0,service_path_filter='Services.v2/ElectricBills')['total'],1)
        self.assertEqual(self.db.requests_page(25,0,service_path_filter='Services.v1/ElectricBillsExtended')['total'],1)
        self.assertEqual(self.db.requests_page(25,0,service_path_filter='Services.v1/ElectricBills%')['total'],0)
        self.assertEqual(self.db.requests_page(25,0,service_path_filter='Services.v1/ElectricBills_')['total'],0)
        self.assertEqual(self.db.requests_page(25,0,service_path_filter='Services.v1/ElectricBills',role='business')['total'],2)
        self.assertEqual(self.db.requests_page(25,0,service_path_filter='Services.v1/ElectricBills',role='support')['total'],0)

    def test_postgres_placeholder_simulated_for_exact_service_filter(self):
        from tests.test_viewer_install_regressions import StrictPgPercentConnection
        native=self.db.conn
        self.db.conn=StrictPgPercentConnection(native)
        self.db.sqlite=False
        try:
            self.assertEqual(self.db.requests_page(25,0,service_path_filter='Services.v1/ElectricBills')['total'],2)
            self.assertEqual(self.db.requests_page(25,0,service_path_filter='Services.v1/ElectricBills%')['total'],0)
        finally:
            self.db.conn=native
            self.db.sqlite=True

    def test_operator_changes_survive_rebuild_without_changing_all_requests(self):
        before=self.db.metrics()
        self.db.update_service_role('Services.v1/ElectricBills','unknown','unknown','manual review')
        all_roles=self.db.service_roles(100)
        self.assertEqual(all_roles['role_totals']['unknown'],4)
        self.db.rebuild()
        self.assertEqual(self.db.service_roles(100)['role_totals']['unknown'],4)
        self.assertEqual(self.db.metrics()['requests'],before['requests'])
        self.assertEqual(self.db.requests_page(25,0,service_path_filter='Services.v1/ElectricBills',role='unknown')['total'],2)
        self.assertEqual(self.db.requests_page(25,0,role='business')['total'],0)
        self.assertEqual(len(self.db.all('SELECT * FROM viewer_service_role_history')),1)

    def test_session_request_filter_equals_business_view_and_preserves_other_calls(self):
        key=self.db.lookup_request(RIDS[0])['session_key']
        business=self.db.requests_page(25,0,session_key=key,role='business')
        self.assertEqual(business['total'],2) # only known v1; v2 unknown
        self.assertEqual(len({r['request_key'] for r in business['items']}),2)
        self.assertEqual(self.db.requests_page(25,0,session_key=key)['total'],7)
        with self.assertRaises(ValueError):self.db.requests_page(25,0,session_key='BADKEY')

    def test_catalog_and_request_templates_link_exact_scope(self):
        env=Environment(loader=FileSystemLoader(str(ROOT/'review_ui/templates')),
              undefined=StrictUndefined,autoescape=select_autoescape(['html']))
        from p24_foundation.viewer_display_time import tehran_time
        env.filters['tehran_time']=tehran_time
        env.globals['url_for']=lambda endpoint,**kwargs: '/' + endpoint + '?' + '&'.join(f'{k}={v}' for k,v in kwargs.items())
        records=self.db.service_roles(25)
        for r in records['items']:r['csrf']='0'*64
        html=env.get_template('viewer_services.html').render(result=records,search='',role='',page=1,limit=25,version='0.2.3')
        self.assertIn('راهنمای نقش‌ها',html)
        self.assertIn('role_totals',repr(records))
        self.assertIn('sample_request_key',repr(records))
        self.assertIn('service_path=Services.v1/ElectricBills',html)
        self.assertIn('تمام درخواست‌های این API',html)
        req=self.db.requests_page(5,0,session_key=self.db.lookup_request(RIDS[0])['session_key'],role='business')
        html=env.get_template('viewer_requests.html').render(result=req,page=1,limit=5,session='',
            session_key=self.db.lookup_request(RIDS[0])['session_key'],request_id='',service='',service_path_filter='Services.v1/ElectricBills',
            role='business',outcome='',start='',end='',internal=False,version='0.2.3')
        self.assertIn('name="session_key"',html)
        self.assertIn('name="service_path"',html)
        self.assertIn('role=business',html)

    @unittest.skipIf(create_viewer_app is None,'Flask unavailable: actual route HTTP requires native Windows validation')
    def test_http_old_session_url_redirects_and_catalog_links_work(self):
        app=create_viewer_app({'sqlite_path':self.dbpath,'keys_path':self.keys})
        cli=app.test_client()
        key=self.db.lookup_request(RIDS[0])['session_key']
        old=cli.get('/session/'+key)
        self.assertEqual(old.status_code,302)
        self.assertIn('session_key='+key,old.headers['Location'])
        self.assertIn('role=business',old.headers['Location'])
        page=cli.get(old.headers['Location'])
        self.assertEqual(page.status_code,200)
        self.assertEqual(cli.get('/services').status_code,200)
        self.assertEqual(cli.get('/requests?service_path=Services.v1%2FElectricBills').status_code,200)
        self.assertEqual(cli.get('/requests?session_key=BAD').status_code,400)

if __name__=='__main__':unittest.main()
