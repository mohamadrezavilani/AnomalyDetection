"""Small native pilot cannot be mistaken for operational acceptance."""
import ast
from pathlib import Path
import unittest
from p24_foundation.viewer_acceptance import evaluate_pilot,evaluate_development_smoke

ROOT=Path(__file__).resolve().parents[1]


def sample():
    return dict(
        mode='live_owner_postgresql_smoke',status='SMOKE_PASS',requested_windows=2,
        required_rechecks=0,restart_performed=True,restart_checkpoint_preserved=True,
        windows=[dict(status='PUBLISHED',mode='forward',total_cycle_seconds=245.36),
                 dict(status='PUBLISHED',mode='forward',total_cycle_seconds=240)],
        rechecks=[],http_errors=0,
        http_latency={k:dict(samples=5,p95_seconds=.5) for k in ('home','session','request')},
        before={'backlog_windows':13},after={'backlog_windows':11})


class DevelopmentSmokeTests(unittest.TestCase):
    def test_two_forward_and_reconnect_is_valid_smoke_only(self):
        row=sample()
        self.assertTrue(all(evaluate_development_smoke(row).values()))
        self.assertFalse(all(evaluate_pilot(row).values()))
        self.assertFalse(evaluate_pilot(row)['six_forward_windows_complete'])
        self.assertFalse(evaluate_pilot(row)['rechecks_complete'])

    def test_no_vacuous_empty_smoke_or_fake_reconnect(self):
        for edit in ({'windows':[]}, {'restart_checkpoint_preserved':False},
                     {'http_errors':1}, {'http_latency':{}},
                     {'requested_windows':6}, {'required_rechecks':2}):
            with self.subTest(edit=edit):
                row=sample();row.update(edit)
                self.assertFalse(all(evaluate_development_smoke(row).values()))

    def test_bad_cycle_and_recheck_rejected(self):
        row=sample();row['windows'][1]['total_cycle_seconds']=301
        self.assertFalse(evaluate_development_smoke(row)['bounded_forward_windows'])
        row=sample();row['required_rechecks']=1
        self.assertFalse(evaluate_development_smoke(row)['bounded_rechecks'])
        row['rechecks']=[dict(status='PUBLISHED',mode='recheck',total_cycle_seconds=12)]
        self.assertTrue(evaluate_development_smoke(row)['bounded_rechecks'])
        row['rechecks'][0]['status']='FAILED'
        self.assertFalse(evaluate_development_smoke(row)['bounded_rechecks'])

    def test_full_pilot_keeps_nonvacuous_six_plus_two(self):
        row=sample()
        row['requested_windows']=6;row['required_rechecks']=2
        row['windows']=[dict(status='PUBLISHED',mode='forward',total_cycle_seconds=10) for _ in range(6)]
        row['rechecks']=[dict(status='PUBLISHED',mode='recheck',total_cycle_seconds=11) for _ in range(2)]
        self.assertTrue(all(evaluate_pilot(row).values()))
        self.assertFalse(evaluate_development_smoke(row)['bounded_forward_windows'])

    def test_cli_is_statically_parseable_and_requires_explicit_smoke(self):
        module=ast.parse((ROOT/'tools/run_viewer_pilot.py').read_text())
        self.assertTrue(any(isinstance(n,ast.FunctionDef) and n.name=='main' for n in module.body))
        source=(ROOT/'tools/run_viewer_pilot.py').read_text()
        self.assertIn("ap.add_argument('--smoke',action='store_true'",source)
        self.assertIn('if args.smoke:',source)
        self.assertIn("report['status']='SMOKE_PASS'",source)
        self.assertIn("report['status']='PASS'",source)


if __name__=='__main__':unittest.main()
