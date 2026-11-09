"""The one-window command retains the normal CLI and saves bounded evidence."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from p24_foundation.viewer_data import ViewerDB
from tools import profile_viewer_window as profile


class WindowProfileTests(unittest.TestCase):
    def test_normal_publication_records_timings_and_restores_process_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'window.json';before=sys.argv
            old=ViewerDB.__dict__.get('progress_callback')
            def normal_cli():
                self.assertEqual(sys.argv[1:3],['live-once','--config'])
                db=object.__new__(ViewerDB);db.conn=object()
                db.progress('ingest',processed=500,total=500)
                print(json.dumps(dict(status='PUBLISHED',total_cycle_seconds=125,generation=5)))
            with patch.object(profile,'run_viewer',side_effect=normal_cli),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(profile.main(['--config','private.py','--out',str(out)]),0)
            report=json.loads(out.read_text())
            self.assertEqual(report['status'],'PUBLISHED_UNDER_BUDGET')
            self.assertEqual(report['progress'][0]['progress']['processed'],500)
            self.assertIs(sys.argv,before)
            self.assertIs(ViewerDB.__dict__.get('progress_callback'),old)

    def test_published_slow_cycle_is_not_accepted_as_online(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'window.json'
            def slow_cli():print(json.dumps(dict(status='PUBLISHED',total_cycle_seconds=376)))
            with patch.object(profile,'run_viewer',side_effect=slow_cli),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(profile.main(['--config','private.py','--out',str(out)]),2)
            report=json.loads(out.read_text())
            self.assertEqual(report['status'],'PUBLISHED_OVER_BUDGET')
            self.assertEqual(report['result']['status'],'PUBLISHED')

    def test_failed_command_still_writes_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'window.json'
            with patch.object(profile,'run_viewer',side_effect=SystemExit(2)),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(profile.main(['--config','private.py','--out',str(out)]),2)
            self.assertEqual(json.loads(out.read_text())['status'],'FAILED')
