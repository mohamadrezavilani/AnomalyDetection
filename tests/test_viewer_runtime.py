"""Console back-pressure and incomplete evidence cannot become release success."""
import copy
import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from p24_foundation.viewer_runtime import ProgressConsole,atomic_json
from p24_foundation.viewer_acceptance import evaluate_pilot


def completed_pilot():
    return dict(requested_windows=6,required_rechecks=2,
        windows=[dict(status='PUBLISHED',mode='forward',total_cycle_seconds=220) for _ in range(6)],
        rechecks=[dict(status='PUBLISHED',mode='recheck',total_cycle_seconds=50) for _ in range(2)],
        restart_performed=True,restart_checkpoint_preserved=True,http_errors=0,
        http_latency={kind:dict(samples=10,p95_seconds=.3) for kind in ('home','session','request')},
        before=dict(backlog_windows=20),after=dict(backlog_windows=17))


class RuntimeTests(unittest.TestCase):
    def test_paused_console_never_blocks_worker_progress_and_queue_is_bounded(self):
        entered=threading.Event();release=threading.Event()
        class Paused:
            def write(self,value):entered.set();release.wait(3)
            def flush(self):pass
        console=ProgressConsole(Paused(),capacity=4,heartbeat_seconds=0)
        try:
            console.emit(dict(status='first'));self.assertTrue(entered.wait(1))
            began=time.monotonic()
            for n in range(1000):console.progress(dict(stage='ingest',processed=n))
            console.close(timeout=.01)
            self.assertLess(time.monotonic()-began,1)
            self.assertLessEqual(console.pending.qsize(),4);self.assertGreater(console.dropped,0)
        finally:release.set();console.close()

    def test_closed_console_does_not_change_worker_results(self):
        stream=io.StringIO();stream.close()
        console=ProgressConsole(stream,heartbeat_seconds=0)
        console.progress(dict(stage='before_commit'));console.close()
        self.assertEqual(console.io_errors,1)

    def test_atomic_report_failure_preserves_previous_complete_json(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'result.json';atomic_json(path,dict(status='RUNNING',windows=[1]))
            with patch.object(Path,'replace',side_effect=OSError('controlled')):
                with self.assertRaises(OSError):atomic_json(path,dict(status='PASS'))
            self.assertEqual(json.loads(path.read_text()),dict(status='RUNNING',windows=[1]))
            self.assertEqual(list(Path(temp).glob('*.tmp')),[])


class AcceptanceTests(unittest.TestCase):
    def test_complete_report_passes_all_explicit_gates(self):
        self.assertTrue(all(evaluate_pilot(completed_pilot()).values()))

    def test_six_published_windows_without_rechecks_cannot_pass(self):
        report=completed_pilot();report['rechecks']=[]
        self.assertFalse(evaluate_pilot(report)['rechecks_complete'])

    def test_empty_window_list_cannot_pass_vacuous_all(self):
        report=completed_pilot();report['windows']=[]
        self.assertFalse(evaluate_pilot(report)['six_forward_windows_complete'])

    def test_nonfinite_negative_and_boolean_durations_never_pass(self):
        for value in (float('nan'),float('inf'),-1,True,None):
            with self.subTest(value=value):
                report=completed_pilot();report['windows'][0]['total_cycle_seconds']=value
                self.assertFalse(evaluate_pilot(report)['all_cycles_under_budget'])

    def test_cycle_budget_is_300_even_with_longer_global_deadline(self):
        report=completed_pilot();report['max_minutes']=45
        report['windows'][0]['total_cycle_seconds']=303.156
        self.assertFalse(evaluate_pilot(report)['all_cycles_under_budget'])

    def test_missing_ui_samples_or_backlog_snapshot_cannot_pass(self):
        report=completed_pilot();report['http_latency']['request']['samples']=0
        report.pop('after')
        checks=evaluate_pilot(report)
        self.assertFalse(checks['ui_budget_met']);self.assertFalse(checks['backlog_not_growing'])
