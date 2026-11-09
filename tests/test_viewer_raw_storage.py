"""Full DB-backed evidence and non-destructive raw hydration regression tests."""
import gzip
import json
import tempfile
import unittest
from pathlib import Path

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
try:
    from p24_foundation.viewer_ui import create_viewer_app
except ImportError:
    create_viewer_app=None


SESSION='AA12FF34FF56FF78FF90FF12FF34FF56'
RID='a5e947d2-3856-4b49-8e50-278be06a7001'
OTHER='a5e947d2-3856-4b49-8e50-278be06a7002'


def fixture(index, rid, call, raw):
    return {'_source_id':f'logs-test-20261024:{index}', '@timestamp':'2026-10-24T04:20:00.1234567Z',
            'RequestID':rid, 'Session':SESSION,'IP':'192.0.2.4','CallPath':call,
            'message':raw,'extra':{'nested':'<script>alert(1)</script>'}}


class RawStorageTests(unittest.TestCase):
    def setUp(self):
        self.dir=tempfile.TemporaryDirectory();self.addCleanup(self.dir.cleanup)
        root=Path(self.dir.name)
        self.opts={'sqlite_path':root/'db.sqlite','keys_path':root/'private-keys.json'}
        generate_keys(self.opts['keys_path'])
        self.file=root/'window.json.gz'
        self.events=[fixture('A',RID,'Services.v1/ElectricBills Line:100',
                    'POST (G00000 | successful)\nInput:[{"ElectricityBillID":"000021234"}]\nOutput:[{"Customer":"تست","Token":"secret-otp"}]'),
                    fixture('B',OTHER,'Core.v1/UserServiceQueryBookmark Line:12','POST (G00000 | successful)')]
        self.expected={'window_start':'2026-10-24T04:00:00Z','window_end':'2026-10-24T04:25:00Z','logs':self.events}
        with gzip.open(self.file,'wt',encoding='utf8') as f:json.dump(self.expected,f,ensure_ascii=False)

    def test_full_evidence_survives_gzip_deletion_and_no_duplicate(self):
        with ViewerDB(**self.opts) as db:
            db.init();self.assertEqual(db.ingest([self.file])[0]['status'],'IMPORTED')
            db.rebuild();self.assertTrue(db.raw_coverage()['complete'])
            req=db.lookup_request(RID);self.assertEqual(req['raw_request_id'],RID)
            sk=req['session_key']
            self.assertEqual(db.sessions(10)['items'][0]['alias'],SESSION)
            main=db.actions(sk,10,category='main')['items']
            self.assertEqual([r['name'] for r in main],['ElectricBills'])
            raw_event=db.evidence(req['request_key'])['items'][0]
            source=db.get_raw(raw_event['origin_key'],raw_event['version_key'])
            self.assertEqual(source['message'],self.events[0]['message'])
            self.assertEqual(source['extra'],self.events[0]['extra'])
            self.assertEqual(db.ingest([self.file])[0]['status'],'ALREADY_IMPORTED')
            self.assertEqual(db.raw_coverage()['raw_events'],2)
            reqkey=req['request_key'];origin=raw_event['origin_key'];version=raw_event['version_key']
        self.file.unlink()
        with ViewerDB(**self.opts) as db:
            self.assertEqual(db.raw_request_id(reqkey),RID)
            self.assertEqual(db.get_raw(origin,version)['message'],self.events[0]['message'])
    @unittest.skipUnless(create_viewer_app is not None,'Flask not available in this execution environment')
    def test_browser_raw_evidence_escaped(self):
        with ViewerDB(**self.opts) as db:
            db.init();db.ingest([self.file]);db.rebuild()
            req=db.lookup_request(RID)
            row=db.evidence(req['request_key'])['items'][0]
            origin,version=row['origin_key'],row['version_key']
        app=create_viewer_app(self.opts)
        app.config['TESTING']=True
        with app.test_client() as client:
            resp=client.get(f'/evidence/{origin}/{version}')
            self.assertEqual(resp.status_code,200)
            self.assertIn('000021234',resp.get_data(as_text=True))
            self.assertIn('secret-otp',resp.get_data(as_text=True))
            self.assertNotIn('<script>alert(1)</script>',resp.get_data(as_text=True))
            self.assertIn('&lt;script&gt;',resp.get_data(as_text=True))

    def test_upgrade_old_hash_only_db_non_destructive_replay(self):
        with ViewerDB(**self.opts) as db:
            db.init();db.ingest([self.file]);db.rebuild()
            db.sql('DELETE FROM viewer_raw_events');db.conn.commit()
            self.assertEqual(db.raw_coverage()['missing'],2)
            self.assertEqual(db.hydrate_raw([self.file])[0]['added'],2)
            self.assertEqual(db.hydrate_raw([self.file])[0]['added'],0)
            self.assertTrue(db.raw_coverage()['complete'])
            self.assertEqual(db.metrics()['requests'],2)
            self.assertEqual(db.metrics()['events'],2)
            self.assertEqual(db.one('SELECT COUNT(*) AS n FROM viewer_service_roles')['n'],2)

    def test_hydration_rejects_unrelated_files(self):
        with ViewerDB(**self.opts) as db:
            db.init()
            r=db.hydrate_raw([self.file])[0]
            self.assertEqual(r['status'],'SHA_MISMATCH_OR_NOT_IMPORTED')
            self.assertEqual(db.raw_coverage()['raw_events'],0)

if __name__=='__main__':unittest.main()
