"""Supervision/crash probes plus native composition; no real Elasticsearch access."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

from p24_foundation.errors import FoundationError
from p24_foundation.pipeline import run,ownership,read_state,execute,validate_spec
from p24_foundation.replay import _write_report


def spec(**changes):
    result=dict(version='p24-pipeline.1',start='2026-01-01T00:00:00+00:00',windows=2,lag_seconds=0,
                window_timeout_seconds=10,config='/private/config.py',target_root='/private/legacy',
                stream='pipeline-test',index_pattern='fixture-*',rank_cutoff='1/20',persist_candidates=False)
    return result|changes


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)/'state with spaces'
        self.calls=[]

    def launch(self,command,timeout):
        ordinal=int(command[-1]);self.calls.append(ordinal)
        job=self.root/f'window_{ordinal:04d}';job.mkdir()
        result=dict(status='completed',publication_id=str(uuid.uuid4()),generation=ordinal+1)
        _write_report(job/'result.json',result,create=True)
        return result

    def test_completed_windows_are_ordered_and_not_replayed_on_restart(self):
        result=run(spec(),self.root,['worker'],launch=self.launch)
        self.assertEqual(result['status'],'completed');self.assertEqual(self.calls,[0,1])
        run(spec(),self.root,['worker'],launch=self.launch)
        self.assertEqual(self.calls,[0,1]);self.assertIsNone(read_state(self.root/'state.json')['in_flight'])

    def test_uncertain_child_failure_stops_and_restart_requires_reconciliation(self):
        def fail(command,timeout):
            self.assertEqual(read_state(self.root/'state.json')['in_flight'],0)
            raise FoundationError('private_driver_message')
        with self.assertRaises(FoundationError):run(spec(),self.root,['worker'],launch=fail)
        state=read_state(self.root/'state.json');self.assertEqual(state['status'],'requires_reconciliation')
        with self.assertRaisesRegex(FoundationError,'pipeline_requires_reconciliation'):
            run(spec(),self.root,['worker'],launch=self.launch)
        self.assertEqual(self.calls,[]);self.assertNotIn('private_driver_message',(self.root/'state.json').read_text())

    def test_completed_prefix_survives_failure_without_skipping_the_failed_window(self):
        def launch(command,timeout):
            if command[-1]=='1':raise FoundationError('failed')
            return self.launch(command,timeout)
        with self.assertRaises(FoundationError):run(spec(),self.root,['worker'],launch=launch)
        state=read_state(self.root/'state.json');self.assertEqual((state['completed_windows'],state['in_flight']),(1,1))
        self.assertEqual(self.calls,[0])

    def test_child_stdout_is_not_confirmation_without_matching_durable_result(self):
        with self.assertRaisesRegex(FoundationError,'pipeline_state_unreadable'):
            run(spec(),self.root,['worker'],launch=lambda *args:dict(status='completed',publication_id=str(uuid.uuid4()),generation=1))
        self.assertEqual(read_state(self.root/'state.json')['status'],'requires_reconciliation')

    def test_schedule_waits_until_window_end_plus_lag_and_can_stop_cleanly(self):
        waits=[]
        def stop(seconds):waits.append(seconds);raise KeyboardInterrupt()
        result=run(spec(start='2099-01-01T00:00:00+00:00'),self.root,['worker'],launch=self.launch,pause=stop)
        self.assertEqual(waits,[1]);self.assertEqual(result['status'],'stopped');self.assertEqual(self.calls,[])
        self.assertIsNone(read_state(self.root/'state.json')['in_flight'])

    def test_changed_spec_cannot_resume_existing_state(self):
        run(spec(windows=1),self.root,['worker'],launch=self.launch)
        with self.assertRaisesRegex(FoundationError,'pipeline_spec_changed'):
            run(spec(windows=2),self.root,['worker'],launch=self.launch)

    def test_owner_lease_blocks_another_process_and_releases_after_exit(self):
        command=[sys.executable,'-c',
          'import sys; from p24_foundation.pipeline import ownership; from pathlib import Path\nwith ownership(Path(sys.argv[1])): print("acquired")',str(self.root)]
        with ownership(self.root):
            child=subprocess.run(command,capture_output=True,text=True)
            self.assertNotEqual(child.returncode,0)
        child=subprocess.run(command,capture_output=True,text=True)
        self.assertEqual(child.returncode,0);self.assertIn('acquired',child.stdout)

    def test_timeout_kills_and_reaps_child(self):
        process=unittest.mock.Mock();process.wait.side_effect=[subprocess.TimeoutExpired('worker',1),0];process.poll.return_value=None
        with patch('p24_foundation.pipeline.subprocess.Popen',return_value=process):
            with self.assertRaisesRegex(FoundationError,'pipeline_window_unconfirmed'):execute(['worker'],1)
        process.kill.assert_called_once();self.assertEqual(process.wait.call_count,2)

    def test_interrupt_reaps_child_and_marks_inflight_for_reconciliation(self):
        process=unittest.mock.Mock();process.wait.side_effect=[KeyboardInterrupt(),0];process.poll.return_value=None
        with patch('p24_foundation.pipeline.subprocess.Popen',return_value=process):
            result=run(spec(),self.root,['worker'])
        process.kill.assert_called_once();self.assertEqual(result['status'],'requires_reconciliation')

    def test_invalid_schedule_bounds_and_rank_fail_before_writes(self):
        for changes in [dict(start='2026-01-01T00:01:00Z'),dict(start='2026-01-01T00:00:00'),dict(windows=True),
                        dict(windows=129),dict(lag_seconds=-1),dict(window_timeout_seconds=0),dict(rank_cutoff='1e-2'),
                        dict(rank_cutoff='1/0'),dict(stream='bad stream'),dict(persist_candidates=1)]:
            with self.subTest(changes=changes),self.assertRaises(FoundationError):
                run(spec(**changes),self.root,['worker'],launch=self.launch)
        self.assertFalse(self.root.exists())

    def test_bad_or_oversized_worker_success_does_not_leak_output(self):
        # Generate large stdout inside the child; Windows command lines are bounded.
        for code in ["print('{\"status\":\"completed\",\"publication_id\":\"invalid\"}',end='')",
                     "print('secret'*12000,end='')"]:
            command=[sys.executable,'-c',code]
            with self.assertRaisesRegex(FoundationError,'pipeline_window_unconfirmed'):execute(command,10)


class PipelinePostgresTests(unittest.TestCase):
    connection=None;database_config=None

    @classmethod
    def setUpClass(cls):
        if cls.connection is None:raise unittest.SkipTest('disposable PostgreSQL configuration required')
        from p24_foundation.store import initialize
        initialize(cls.connection)

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.namespace='pipeline_'+uuid.uuid4().hex

    def launch_pipeline(self,persist=False,fail_report=False):
        from tools.run_pipeline import cycle
        from tests.helpers import TEST_KEYS,document
        from tests.test_collector_pipeline import packet_for
        from p24_foundation.privacy import canonical
        settings=dict(database=self.database_config,namespace=self.namespace,keys_path=self.root/'keys',vault_path=self.root/'vault')
        def collect(args):
            row=document(rid=args.start,oid=args.start,at=args.start)
            args.output.write_bytes(canonical(packet_for([row],args.start,args.end)))
            return dict(status='captured')
        def launch(command,timeout):return cycle(self.root,int(command[-1]))
        with patch('p24_foundation.config.read_config',return_value=settings),patch('p24_foundation.privacy.Keys.read',return_value=TEST_KEYS),patch('tools.collector_pipeline.collect',side_effect=collect):
            if fail_report:
                with patch('tools.detect_behavior.write_report',side_effect=FoundationError('write_failed')):
                    return run(spec(persist_candidates=persist),self.root,['worker'],launch=launch)
            return run(spec(persist_candidates=persist),self.root,['worker'],launch=launch)

    def test_native_two_windows_publish_score_and_persian_reports_with_preserved_capture(self):
        result=self.launch_pipeline()
        self.assertEqual(result['completed_windows'],2)
        first=read_state(self.root/'window_0000/report.json');second=read_state(self.root/'window_0001/report.json')
        self.assertEqual(first['status'],'warming_up');self.assertEqual(second['unsupported_units'],1)
        self.assertEqual(second['evaluations'][0]['reason'],'insufficient_personal_history')
        self.assertTrue((self.root/'window_0001/report.html').is_file())
        self.assertEqual(read_state(self.root/'window_0001/result.json')['generation'],2)
        self.assertTrue((self.root/'window_0000/capture.json').is_file())

    def test_native_explicit_persistence_records_abstention_and_keeps_priority_independent(self):
        self.launch_pipeline(persist=True)
        report=read_state(self.root/'window_0001/report.json')
        self.assertEqual(report['unsupported_units'],1);self.assertEqual(report['candidates'],[])
        rows=self.connection.execute('SELECT assessment_state,measurements FROM p24_next.finding WHERE namespace_id=(SELECT namespace_id FROM p24_next.namespace WHERE application_key=%s)',(self.namespace,)).fetchall()
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0][1]['priority'],'unrated');self.assertEqual(rows[0][1]['fraud_verdict'],'not_established')

    def test_native_postcommit_report_failure_leaves_commit_identity_and_blocks_auto_retry(self):
        with self.assertRaisesRegex(FoundationError,'write_failed'):self.launch_pipeline(fail_report=True)
        state=read_state(self.root/'state.json')
        self.assertEqual((state['completed_windows'],state['in_flight']),(1,1))
        self.assertTrue((self.root/'window_0001/publication.json').exists())
        self.assertFalse((self.root/'window_0001/result.json').exists())
