"""LC3E: bounded replay of actual stored event bodies; fixtures only for CI."""
import gzip,json,sqlite3,tempfile,unittest
from pathlib import Path
from p24_foundation.lc3_replay_audit import _fixture_windows
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from tools.run_lc3e_real_replay import execute,main

class LC3ERealSubsetReplayTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.keys=self.root/'keys.json'
        generate_keys(self.keys)
        self.path=self.root/'source.sqlite'
        files=_fixture_windows(self.root)
        # Real Elasticsearch events have stable _source_id = index:id. Ensure
        # we test the exact source-identity preservation logic.
        for f in files:
            with gzip.open(f,'rt',encoding='utf8') as src: obj=json.load(src)
            for row in obj['logs']:
                row['_source_id']='synthetic-index:'+str(row['_source_id'])
            with gzip.open(f,'wt',encoding='utf8') as dst:json.dump(obj,dst)
        self.db=ViewerDB(sqlite_path=self.path,keys_path=self.keys)
        self.addCleanup(self.db.close)
        self.db.init()
        self.assertEqual(3,len(self.db.ingest(files)))
        self.db.rebuild();self.db.rebuild_payment_contract()
        self.config=self.root/'config.py'
        self.config.write_text('SQLITE_OFFLINE_PATH='+repr(str(self.path))+'\nKEYS_PATH='+repr(str(self.keys))+'\n',encoding='utf8')

    def test_true_replay_stable_across_three_orders_and_matches_source(self):
        result=execute(self.config,sample_limit=1)
        self.assertEqual('COMPLETED',result['status'])
        self.assertEqual(1,result['replayable_requests'])
        self.assertGreaterEqual(result['original_declared_source_windows'],2)
        self.assertTrue(result['order_independent_derived_snapshot'])
        self.assertTrue(result['repeat_import_idempotent'])
        self.assertTrue(result['selected_request_projection_matches_source'])
        self.assertTrue(result['selected_evidence_projection_matches_source'])
        self.assertTrue(all(result['matches_indexed_source_projection_by_table'].values()))
        self.assertEqual(0,result['fully_accepted_end_to_end_cases'])
        self.assertNotIn('raw_payload',json.dumps(result))

    def test_cli_executes_without_modifying_source(self):
        before=self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n']
        outfile=self.root/'witness.json'
        self.assertEqual(0,main(['--config',str(self.config),'--out',str(outfile),'--sample-limit','1']))
        self.assertEqual(before,self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'])
        self.assertTrue(json.loads(outfile.read_text())['read_only_source'])

    def test_missing_stable_source_id_refuses_to_invent_link(self):
        # Replace the only cross-window q1 with a source row with no colon.
        # We use a second source rather than rewriting historic rows in place.
        second=self.root/'incomplete';second.mkdir()
        keys=second/'keys.json';generate_keys(keys)
        files=_fixture_windows(second)
        with ViewerDB(sqlite_path=second/'db.sqlite',keys_path=keys) as db:
            db.init();db.ingest(files);db.rebuild();db.rebuild_payment_contract()
        config=second/'config.py'
        config.write_text('SQLITE_OFFLINE_PATH='+repr(str(second/'db.sqlite'))+'\nKEYS_PATH='+repr(str(keys))+'\n')
        result=execute(config,sample_limit=1)
        self.assertEqual('INSUFFICIENT_REPLAYABLE_SOURCE_EVIDENCE',result['status'])
        self.assertGreater(result['skip_reasons'].get('missing_stable_source_identity',0),0)
        self.assertFalse(result.get('selected_request_projection_matches_source',False))

    def test_parameter_bound_and_unguarded_config_rejected(self):
        for invalid in (-1,0,5):
            self.assertEqual(2,main(['--config',str(self.config),'--out',str(self.root/'reject.json'),'--sample-limit',str(invalid)]))
        bad=self.root/'bad.py'
        bad.write_text('DATABASE='+repr({'dbname':'pishkhan24_shadow'})+'\nKEYS_PATH='+repr(str(self.keys)))
        self.assertEqual(2,main(['--config',str(bad),'--out',str(self.root/'bad.json')]))
        self.assertFalse((self.root/'bad.json').exists())

if __name__=='__main__':unittest.main()
