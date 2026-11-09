"""Installation checks reject altered sources and stale pilot acceptance."""
import hashlib
import contextlib
import io
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch
from tools.check_viewer_install import verify_release,pilot_evidence,check
from tests.test_viewer_runtime import completed_pilot
from p24_foundation.viewer_data import ViewerDB


class InstallCheckTests(unittest.TestCase):
    def test_fresh_init_binds_online_schema_without_fetch_or_key_replacement(self):
        from tools.run_behavior_viewer import main
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);config=root/'private.py';keys=root/'keys.json'
            config.write_text('KEYS_PATH='+repr(str(keys))+'\nSQLITE_OFFLINE_PATH='+repr(str(root/'db'))+
                '\nLIVE_START_UTC="2026-10-26T09:00:00Z"\nELASTICSEARCH='+repr({'host':'http://example.invalid','index_pattern':'logs-*'})+'\n')
            with patch.object(sys,'argv',['viewer','init','--config',str(config)]),patch('p24_foundation.viewer_elastic.ElasticREST') as capture,contextlib.redirect_stdout(io.StringIO()):
                main();before=keys.read_bytes();main()
            capture.assert_not_called();self.assertEqual(keys.read_bytes(),before)
            with ViewerDB(sqlite_path=root/'db',keys_path=keys) as db:
                self.assertEqual(db.one('SELECT generation FROM viewer_live_state')['generation'],0)
                self.assertEqual(db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],0)

    def test_changed_release_code_is_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'app.py';source.write_text('source')
            (root/'RELEASE_MANIFEST.json').write_text(json.dumps(dict(files_sha256={'app.py':hashlib.sha256(source.read_bytes()).hexdigest()})))
            self.assertEqual(verify_release(root)['status'],'PASS')
            source.write_text('changed')
            self.assertEqual(verify_release(root)['mismatches'],['app.py'])

    def test_non_viewer_database_is_rejected_before_connection(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);config=root/'private.py';config.write_text("DATABASE={'dbname':'pishkhan24_shadow'}\n")
            with patch('tools.check_viewer_install.verify_release',return_value=dict(status='PASS')),patch('tools.check_viewer_install.ViewerDB') as connect:
                result=check(config,root=root)
            connect.assert_not_called()
            self.assertEqual(result['failure']['code'],'guard_use_viewer_database')

    def test_old_or_incomplete_pass_cannot_accept_current_release(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'pilot.json';report=completed_pilot()
            report.update(status='PASS',mode='live_owner_postgresql_pilot',runtime_source_sha256='old')
            path.write_text(json.dumps(report))
            with patch('tools.check_viewer_install.runtime_source_digest',return_value='current'):
                self.assertEqual(pilot_evidence(path)['status'],'PENDING')
                report['runtime_source_sha256']='current';report['rechecks']=[];path.write_text(json.dumps(report))
                self.assertEqual(pilot_evidence(path)['status'],'PENDING')

    def test_current_complete_native_pilot_is_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'pilot.json';report=completed_pilot()
            report.update(status='PASS',mode='live_owner_postgresql_pilot',runtime_source_sha256='current')
            path.write_text(json.dumps(report))
            with patch('tools.check_viewer_install.runtime_source_digest',return_value='current'):
                self.assertEqual(pilot_evidence(path)['status'],'PASS')
