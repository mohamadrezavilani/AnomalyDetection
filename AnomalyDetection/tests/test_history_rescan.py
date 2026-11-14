"""Restart historical scheduling without deleting facts or human decisions."""
import json
import os
import unittest
from unittest.mock import patch

from anomaly_detection.history_rescan import prepare,CURSORS,REQUEST
from anomaly_detection.history_scope import STATE_KEY,WRITER_LOCK
from anomaly_detection.history_reset import tehran_boundary
from anomaly_detection.product_pipeline import apply_window
from tests import test_scenario_invalidation_pg as native

DAY='2026-10-01'
START=tehran_boundary(DAY)[1]
REPLAY='a'*32


class RescanValidationTests(unittest.TestCase):
    def test_invalid_replay_identity_does_not_touch_storage(self):
        class Unavailable:
            def state(self,*args):raise AssertionError('invalid input reached storage')
        for identity in (None,'','not-a-uuid','A'*32):
            with self.assertRaises(ValueError):prepare(Unavailable(),DAY,identity)


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native AD cluster not configured')
class NativeHistoryRescanTests(unittest.TestCase):
    setUpClass=classmethod(native.NativeScenarioInvalidationTests.setUpClass.__func__)
    tearDownClass=classmethod(native.NativeScenarioInvalidationTests.tearDownClass.__func__)
    setUp=native.NativeScenarioInvalidationTests.setUp
    window_packet=native.NativeScenarioInvalidationTests.window_packet

    def seed(self):
        apply_window(self.store,self.window_packet())
        for name in CURSORS:self.store.save_state(name,{'next_ns':START+10**15,'after':'old-partial-page'})
        self.store.save_state(STATE_KEY,{'start_ns':START+10**15})
        self.store.save_state('semantic_cursor',{'after':'f'*64,'completed_passes':3})
        self.store.save_state('source_watermark',{'generation':1,'semantic_generation':1})
        self.raw.execute("INSERT INTO anomaly_detection.adp_models VALUES('model','family','{}',1)")
        self.raw.execute("INSERT INTO anomaly_detection.adp_feedback(incident_key,label,note,created_ns,incident_revision) VALUES('incident','confirmed','human review',1,2)")
        self.raw.execute("INSERT INTO anomaly_detection.adp_case_feedback(case_key,label,note,created_ns,case_revision,reviewed_end_ns) VALUES('case','confirmed','human review',1,2,3)")

    def evidence(self):
        tables=self.raw.execute("SELECT tablename FROM pg_tables WHERE schemaname='anomaly_detection' AND tablename<>'adp_state' ORDER BY tablename").fetchall()
        return {r['tablename']:sorted(json.dumps(dict(row),sort_keys=True,default=str) for row in self.raw.execute(
            self.sql.SQL('SELECT * FROM anomaly_detection.{}').format(self.sql.Identifier(r['tablename']))).fetchall()) for r in tables}

    def test_rescan_only_repositions_scheduling_and_preserves_all_fact_model_and_human_tables(self):
        self.seed();before=self.evidence();watermark=self.store.state('source_watermark')
        result=prepare(self.store,DAY,REPLAY)
        self.assertEqual(result['status'],'HISTORY_RESCAN_PREPARED')
        self.assertEqual(self.evidence(),before)
        self.assertEqual(self.store.state('source_watermark'),watermark)
        for name in CURSORS:self.assertEqual(self.store.state(name),{'next_ns':START})
        self.assertEqual(self.store.history_floor_ns,START)
        self.assertEqual(self.store.state('semantic_cursor'),{'after':None,'completed_passes':3})
        # A crash after preparation cannot rewind AD a second time.
        advanced={'next_ns':START+300_000_000_000}
        self.store.save_state('learning_cursor',advanced)
        self.assertEqual(prepare(self.store,DAY,REPLAY)['status'],'HISTORY_RESCAN_ALREADY_PREPARED')
        self.assertEqual(self.store.state('learning_cursor'),advanced)

    def test_active_writer_or_preparation_failure_rolls_back_every_cursor(self):
        self.seed();before=self.store.state('fresh_cursor')
        with self.psycopg.connect(**self.params,dbname=self.name,autocommit=True) as owner:
            owner.execute('SELECT pg_advisory_lock(%s)',(WRITER_LOCK,))
            with self.assertRaisesRegex(ValueError,'AD_WRITER_MUST_BE_STOPPED'):prepare(self.store,DAY,REPLAY)
        self.assertEqual(self.store.state('fresh_cursor'),before)
        self.assertEqual(self.store.state(REQUEST),{})
        save=self.store.save_state
        def fail(name,value):
            if name=='semantic_cursor':raise RuntimeError('controlled_rescan_failure')
            return save(name,value)
        with patch.object(self.store,'save_state',side_effect=fail):
            with self.assertRaises(RuntimeError):prepare(self.store,DAY,REPLAY)
        self.assertEqual(self.store.state('fresh_cursor'),before)
        self.assertEqual(self.store.state(REQUEST),{})

    def test_completed_rescan_accepts_backfilled_window_and_invalidates_existing_scope(self):
        self.seed();prepare(self.store,DAY,REPLAY)
        packet=self.window_packet(2,2)
        packet['source']['captured_at_ns']=START+300_000_000_000
        packet['target_ns']=START
        packet['rows'][0]['anchor_ns']=START+1
        packet['stamp']='historical-publication-2'
        result=apply_window(self.store,packet,cursor_name='learning_cursor')
        self.assertEqual(result['status'],'COMPLETE')
        self.assertEqual(self.store.state('learning_cursor'),{'next_ns':START+300_000_000_000})
        fact=self.raw.execute('SELECT at_ns,revision FROM anomaly_detection.adp_facts').fetchone()
        self.assertEqual(dict(fact),{'at_ns':START+1,'revision':2})
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_models').fetchone()['n'],1)
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_case_feedback').fetchone()['n'],1)


if __name__=='__main__':unittest.main()
