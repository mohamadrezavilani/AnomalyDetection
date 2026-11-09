"""Real finite pilot orchestration/HTTP with synthetic capture and SQLite.

This exercises the driver, not native PostgreSQL or a live ES connection.
"""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_online import initialize_live,bind_stream,publish_capture,iso,SECOND_NS
from p24_foundation.viewer_elastic import stream_key
from tests.test_viewer_online import START,verified_file,FIVE_NS
from tests.test_viewer_r6_service_journey import log
from tools.run_viewer_pilot import main


class PilotIntegrationTests(unittest.TestCase):
    def test_six_windows_real_http_reconnect_two_rechecks_and_durable_progress(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);keys=root/'keys';generate_keys(keys)
            database=root/'viewer';out=root/'pilot.json';capture_dir=root/'captures';capture_dir.mkdir()
            es=dict(host='http://example.invalid',index_pattern='synthetic-*')
            config=root/'config.py'
            config.write_text('KEYS_PATH='+repr(str(keys))+'\nDATABASE='+repr({'dbname':'p24_design_synthetic'})+
                '\nLIVE_START_UTC='+repr(iso(START))+'\nELASTICSEARCH='+repr(es)+
                '\nLIVE='+repr(dict(capture_dir=str(capture_dir),overlap_windows=2,lag_seconds=60))+'\n')
            def row_at(start):
                row=log(start//FIVE_NS,'request_'+str(start),'Services.v1/WaterBills Line:1','POST (G00000 | successful)')
                row['@timestamp']=iso(start+SECOND_NS);return row
            with ViewerDB(sqlite_path=database,keys_path=keys) as db:
                db.init();initialize_live(db);bind_stream(db,start_ns=START,stream_key=stream_key(es))
                publish_capture(db,verified_file(root/'seed.gz',[row_at(START)],START),START,START+FIVE_NS)
            observed=[]
            def capture(start,end,*,cancel_event=None):
                saved=json.loads(out.read_text());observed.append((len(saved['windows']),saved['status']))
                return verified_file(capture_dir/('capture_'+str(len(observed))+'.gz'),[row_at(start)],start)
            def connection(**opts):return ViewerDB(sqlite_path=database,keys_path=opts['keys_path'])
            with patch('tools.run_viewer_pilot.ViewerDB',side_effect=connection),\
                 patch('p24_foundation.viewer_ui.ViewerDB',side_effect=connection),\
                 patch('tools.run_viewer_pilot.ElasticCapture',return_value=capture),\
                 contextlib.redirect_stdout(io.StringIO()):
                code=main(['--config',str(config),'--out',str(out)])
            report=json.loads(out.read_text())
            self.assertEqual(code,0,report.get('checks'))
            self.assertEqual(report['status'],'PASS')
            self.assertEqual((len(report['windows']),len(report['rechecks'])),(6,2))
            self.assertTrue(report['restart_checkpoint_preserved'])
            self.assertTrue(all(report['checks'].values()))
            self.assertLessEqual(observed[1][0],1)
            self.assertEqual(observed[1][1],'RUNNING')
            self.assertEqual(observed[-1],(6,'RUNNING'))
            self.assertEqual(len(observed),8)  # Six captures and two fresh rechecks; no unused seventh window.
            self.assertEqual(report['prefetch']['windows_prefetched'],5)
            self.assertTrue(all(row['new_events']==0 for row in report['rechecks']))
            with ViewerDB(sqlite_path=database,keys_path=keys) as db:
                self.assertEqual(db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],7)
