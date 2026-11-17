"""Late holdout changes must not reuse an immutable model's old calibration."""
from collections import Counter
from copy import deepcopy
import json
import os
import random
import unittest
from unittest.mock import patch

from anomaly_detection import FIVE_NS
from anomaly_detection.product_models import evaluate
from tests.test_product_models import example, SERVICE
from tests import test_scenario_invalidation_pg as native

OTHER = 'Services.v1/ElectricBills'
FAMILIES = ('service_mix', 'isolation_forest', 'service_sequence')


def fixture(family):
    context, history = example(n=180, current=20)
    if family == 'service_mix':
        for row in history:
            row['counts'] = {SERVICE: 10, OTHER: 10}
        context['windows'][0]['counts'] = {SERVICE: 1, OTHER: 19}
        revised = deepcopy(history)
        for row in revised[135:]:
            row['counts'] = {SERVICE: 19, OTHER: 1}
        return context, history, deepcopy(context), revised
    if family == 'isolation_forest':
        rng = random.Random(20261117)
        for row in history:
            row['counts'] = {f'Services.v1/P{k}': rng.randint(2, 20)
                             for k in range(rng.randint(1, 4))}
        revised = deepcopy(history)
        for row in revised[135:]:
            row['counts'] = {f'Services.v1/P{k}': 100000 for k in range(30)}
        return context, history, deepcopy(context), revised
    target = context['target_ns']
    def event(index, at, service):
        return dict(request_key=f'{index:064x}', anchor_ns=at, root_call=service,
                    identity_state='assigned', conflicted=False,
                    request_session_key=context['session_key'])
    context['events'] = [event(i, target-(1200-i)*10**9, SERVICE) for i in range(1200)]
    context['events'] += [event(2000+i, target+i*10**9, OTHER) for i in range(20)]
    changed = deepcopy(context)
    for row in changed['events'][800:1200]:
        row['root_call'] = OTHER
    def summarize(ctx, rows):
        counts = {}
        for row in ctx['events']:
            counts.setdefault(row['anchor_ns']//FIVE_NS*FIVE_NS, Counter())[row['root_call']] += 1
        for row in rows + ctx['windows']:
            row['counts'] = dict(counts.get(row['start_ns'], {}))
    revised = deepcopy(history)
    summarize(context, history)
    summarize(changed, revised)
    return context, history, changed, revised


def pair(family):
    left, past, right, revised = fixture(family)
    choose = lambda ctx, rows: next(d for d in evaluate(ctx, rows) if d['family'] == family)
    return choose(left, past), choose(right, revised)


class CalibrationPinTests(unittest.TestCase):
    def assert_changed_pin(self, family, field):
        old, new = pair(family)
        self.assertNotEqual(old['model'][field], new['model'][field])
        self.assertNotEqual(old['model']['model_id'], new['model']['model_id'])
        self.assertEqual(old['finding_key'], new['finding_key'])
        self.assertEqual(old['model']['cutoff_ns'], new['model']['cutoff_ns'])
        if family == 'isolation_forest':
            self.assertEqual(old['model']['trees'], new['model']['trees'])
        else:
            self.assertEqual(old['status'], 'CANDIDATE')
            self.assertEqual(new['status'], 'NO_DEVIATION_OBSERVED')

    def test_mix_validation_changes_pin_even_with_unchanged_training(self):
        self.assert_changed_pin('service_mix', 'validation_errors')

    def test_if_calibration_changes_pin_even_with_unchanged_trees(self):
        self.assert_changed_pin('isolation_forest', 'calibration_scores')

    def test_sequence_validation_changes_pin_even_with_unchanged_training_order(self):
        self.assert_changed_pin('service_sequence', 'validation_scores')

    def test_future_or_unqualified_rows_do_not_change_pinned_models(self):
        for family in FAMILIES:
            with self.subTest(family=family):
                ctx, rows, _, _ = fixture(family)
                original = next(d for d in evaluate(ctx, rows) if d['family'] == family)
                extra = [dict(rows[0], start_ns=ctx['target_ns']+FIVE_NS, counts={OTHER: 999999}),
                         dict(rows[0], start_ns=rows[0]['start_ns']-FIVE_NS,
                              coverage_complete=False, population_complete=False, counts={OTHER: 999999})]
                again = next(d for d in evaluate(ctx, rows+extra) if d['family'] == family)
                self.assertEqual(original['model'], again['model'])

    def test_current_observation_is_not_part_of_the_model_identity(self):
        for family in FAMILIES:
            with self.subTest(family=family):
                ctx, rows, _, _ = fixture(family)
                original = next(d for d in evaluate(ctx, rows) if d['family'] == family)
                changed = deepcopy(ctx)
                changed['windows'][0]['counts'] = {SERVICE: 19, OTHER: 1}
                for event in changed['events']:
                    if event['anchor_ns'] >= changed['target_ns']:
                        event['root_call'] = SERVICE
                again = next(d for d in evaluate(changed, rows) if d['family'] == family)
                self.assertEqual(original['model'], again['model'])


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'), 'native AD cluster not configured')
class NativeCalibrationPinTests(unittest.TestCase):
    setUpClass = classmethod(native.NativeScenarioInvalidationTests.setUpClass.__func__)
    tearDownClass = classmethod(native.NativeScenarioInvalidationTests.tearDownClass.__func__)
    setUp = native.NativeScenarioInvalidationTests.setUp

    def commit(self, decision, *, fault=None):
        ctx, _, _, _ = fixture(decision['family'])
        ctx['source'] = {'captured_at_ns': ctx['target_ns']+FIVE_NS}
        job = self.raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',
                               (ctx['session_key'], ctx['target_ns'])).fetchone()
        with patch('anomaly_detection.cases.sync_actor'):
            return self.store.complete(job, ctx, [deepcopy(decision)], ctx['target_ns']+FIVE_NS, fault=fault)

    def seed_job(self, family):
        ctx, _, _, _ = fixture(family)
        self.raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns) VALUES(%s,%s)',
                         (ctx['session_key'], ctx['target_ns']))

    def save_pair(self, family):
        self.seed_job(family)
        old, new = pair(family)
        self.assertEqual(self.commit(old)['status'], 'APPLIED')
        self.raw.execute('UPDATE anomaly_detection.adp_jobs SET version=version+1,dirty=TRUE')
        self.assertEqual(self.commit(new)['status'], 'APPLIED')
        saved = {r['model_id']: json.loads(r['body']) for r in
                 self.raw.execute('SELECT model_id,body FROM anomaly_detection.adp_models').fetchall()}
        self.assertEqual(len(saved), 2)
        self.assertEqual(saved[old['model']['model_id']], old['model'])
        self.assertEqual(saved[new['model']['model_id']], new['model'])

    def test_mix_result_commit_preserves_both_immutable_calibrations(self):
        self.save_pair('service_mix')

    def test_if_result_commit_preserves_both_immutable_calibrations(self):
        self.save_pair('isolation_forest')

    def test_sequence_result_commit_preserves_both_immutable_calibrations(self):
        self.save_pair('service_sequence')

    def test_failed_complete_rolls_back_new_pin_and_keeps_previous_finding(self):
        self.seed_job('service_mix')
        old, new = pair('service_mix')
        self.commit(old)
        self.raw.execute('UPDATE anomaly_detection.adp_jobs SET version=version+1,dirty=TRUE')
        before = self.raw.execute('SELECT * FROM anomaly_detection.adp_findings').fetchall()
        def fail():
            raise RuntimeError('fixture-before-commit')
        with self.assertRaisesRegex(RuntimeError, 'fixture-before-commit'):
            self.commit(new, fault=fail)
        self.assertEqual(self.raw.execute('SELECT * FROM anomaly_detection.adp_findings').fetchall(), before)
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_models').fetchone()['n'], 1)
        self.assertEqual(self.commit(new)['status'], 'APPLIED')
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_models').fetchone()['n'], 2)


if __name__ == '__main__':
    unittest.main()
