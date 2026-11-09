"""Differential evidence/identity/payment and rollback checks for final writes."""
from pathlib import Path
import copy
import tempfile
import unittest
from unittest.mock import Mock

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_online import initialize_live, bind_stream, publish_capture
from p24_foundation.viewer_projection_writes import ProjectionWritesMixin, route_projection_statement
from tests.test_viewer_online import START, FIVE_NS, verified_file, snapshot, iso
from tests.test_viewer_r6_service_journey import log, sql
from tools.run_finalized_projection_probe import evaluate


class FinalizedProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        keys = self.root / 'keys.json'
        generate_keys(keys)
        self.databases = []
        for name, legacy in [('legacy', True), ('final', False)]:
            db = ViewerDB(sqlite_path=self.root / (name + '.db'), keys_path=keys)
            db._legacy_projection_writes = legacy
            db.init(); initialize_live(db)
            bind_stream(db, start_ns=START, stream_key='differential')
            self.addCleanup(db.close)
            self.databases.append(db)

    def publish_both(self, rows, *, start=START, mode='forward'):
        path = verified_file(self.root / ('capture-' + str(len(list(self.root.glob('*.gz')))) + '.gz'), rows, start)
        for db in self.databases:
            publish_capture(db, path, start, start + FIVE_NS, mode=mode)
        self.assertEqual(snapshot(self.databases[0]), snapshot(self.databases[1]))
        for table in ('viewer_events', 'viewer_links', 'viewer_raw_events',
                      'viewer_event_captures', 'viewer_capture_projections'):
            a = sorted(map(repr, self.databases[0].all('SELECT * FROM ' + table)))
            b = sorted(map(repr, self.databases[1].all('SELECT * FROM ' + table)))
            self.assertEqual(a, b, table)

    def test_old_new_payment_groups_late_identity_conflict_and_manual_roles_match_legacy(self):
        first = [log(1, 'pay', 'DBPath.x.ud_prc_paymentExists', sql('ud_prc_paymentExists', paymentKey='K')),
                 log(2, 'pay', 'Core.v1/WalletPayment Line:1', 'POST (G00000 | successful)'),
                 log(3, 'late', 'ClientAyanCoTopUp.ProductReserve Line:1', 'Output:[]'),
                 log(4, 'repeat', 'Services.v1/WaterBills Line:1', 'POST (G00000 | successful)'),
                 log(5, 'market', 'Public.v1/ExchangeGold Line:1', 'POST (G00000 | successful)')]
        self.publish_both(first)
        for db in self.databases:
            db.update_service_role('Services.v1/WaterBills', 'unknown', 'unknown', 'keep this choice')
        late = log(6, 'late', 'Services.v1/TopUpProductPurchase Line:7', 'POST (G00000 | successful)')
        late['@timestamp'] = iso(START + FIVE_NS + 1_000_000_000)
        late['IP'] = '192.0.2.99'
        repeat = log(7, 'repeat-two', 'Services.v1/WaterBills Line:1', 'POST (G00000 | successful)')
        repeat['@timestamp'] = iso(START + FIVE_NS + 2_000_000_000)
        bridge = log(8, 'callback', 'DBPath.x.ud_prc_paymentExists', sql('ud_prc_paymentExists', paymentKey='K'))
        bridge['@timestamp'] = iso(START + FIVE_NS + 3_000_000_000)
        self.publish_both([late, repeat, bridge], start=START + FIVE_NS)
        changed = copy.deepcopy(first[0]); changed['RequestID'] = 'other-pay'
        changed['message'] = sql('ud_prc_paymentExists', paymentKey='K2')
        self.publish_both([changed, *first[1:]], mode='recheck')
        final = self.databases[1]
        self.assertEqual(final.lookup_request('pay')['conflicted'], 1)
        self.assertEqual(final.lookup_request('other-pay')['conflicted'], 1)
        self.assertEqual(final.one("SELECT role,note FROM viewer_service_roles WHERE service_path='Services.v1/WaterBills'"),
                         {'role': 'unknown', 'note': 'keep this choice'})
        self.assertNotEqual(final.lookup_request('repeat')['request_key'], final.lookup_request('repeat-two')['request_key'])

    def test_unchanged_rebuild_writes_no_permanent_projection_rows(self):
        self.publish_both([log(1, 'r', 'Services.v1/ElectricBills Line:1', 'POST (GD2016 | unavailable)')])
        db = self.databases[1]
        before = snapshot(db)
        relations = db.all("SELECT name,rootpage FROM sqlite_master WHERE type='table' ORDER BY name")
        events = []; db.progress_callback = events.append
        key = db.lookup_request('r')['request_key']
        db.rebuild(request_keys=[key], commit=False)
        db.rebuild_payment_contract(request_keys=[key], commit=False)
        db.conn.commit()
        merges = [e for e in events if e['stage'] == 'projection_publish_complete']
        self.assertEqual(len(merges), 6)
        self.assertTrue(all(e['written_rows'] == 0 and e['deleted_rows'] == 0 for e in merges))
        self.assertEqual(before, snapshot(db))
        self.assertEqual(relations, db.all("SELECT name,rootpage FROM sqlite_master WHERE type='table' ORDER BY name"))

    def test_partial_final_merge_cancels_entire_publication_and_routes_restore(self):
        self.publish_both([log(1, 'r', 'Services.v1/WaterBills Line:1', 'POST (G00000 | successful)')])
        db = self.databases[1]
        before = snapshot(db); state = db.one('SELECT * FROM viewer_live_state')
        row = log(2, 'r2', 'Services.v1/WaterBills Line:1', 'POST (G00000 | successful)')
        row['@timestamp'] = iso(START + FIVE_NS + 1_000_000_000)
        path = verified_file(self.root/'abort.gz', [row], START + FIVE_NS)
        def fail(event):
            if event['stage'] == 'projection_publish_complete':
                raise RuntimeError('cancel_after_one_final_table')
        db.progress_callback = fail
        with self.assertRaisesRegex(RuntimeError, 'cancel_after_one_final_table'):
            publish_capture(db, path, START + FIVE_NS, START + 2*FIVE_NS)
        db.progress_callback = None
        self.assertIsNone(db._projection_routes)
        self.assertEqual(before, snapshot(db))
        self.assertEqual(state, db.one('SELECT * FROM viewer_live_state'))
        self.assertEqual(db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'], 1)
        publish_capture(db, path, START + FIVE_NS, START + 2*FIVE_NS)
        self.assertEqual(db.one('SELECT COUNT(*) AS n FROM viewer_requests')['n'], 2)

    def test_routing_preserves_literal_values(self):
        statement = "SELECT 'viewer_requests', 'it''s viewer_actions' FROM viewer_requests"
        self.assertEqual(route_projection_statement(statement, {'viewer_requests': 'viewer_build_requests'}),
                         "SELECT 'viewer_requests', 'it''s viewer_actions' FROM viewer_build_requests")

    def test_postgres_scoped_delete_uses_indexable_array_only_for_small_fraction(self):
        for table, key, size, estimate, strategy in (
            ('viewer_requests', 'request_key', 26_000, 1_300_000, 'array'),
            ('viewer_requests', 'request_key', None, 1_300_000, 'subquery'),
            ('viewer_requests', 'request_key', 26_000, 200_000, 'subquery'),
            ('viewer_requests', 'request_key', 26_000, -1, 'subquery'),
            ('viewer_requests', 'request_key', 40_000, 2_000_000, 'subquery'),
            ('viewer_actions', 'action_key', 26_000, 1_300_000, 'array'),
            ('viewer_contract_edges', 'edge_key', 26_000, 1_300_000, 'subquery'),
        ):
            with self.subTest(table=table,size=size,estimate=estimate):
                db=Mock()
                db.sqlite=False
                db.one.return_value={'rows':estimate}
                db.sql.return_value.rowcount=0
                stage='viewer_build_'+table.removeprefix('viewer_')
                ProjectionWritesMixin._publish_finalized_projection(
                    db,table,stage,[key],scope_size=size)
                statement=db.sql.call_args_list[0].args[0]
                expected='= ANY (ARRAY(' if strategy=='array' else ' IN (SELECT '
                self.assertIn(expected,statement)
                self.assertIn(f'NOT EXISTS (SELECT 1 FROM {stage} s WHERE s.{key}=d.{key})',statement)
                self.assertEqual(db.progress.call_args.kwargs['delete_scope_strategy'],strategy)

    def test_probe_distinguishes_forward_recheck_and_rolled_back_checkpoint(self):
        before={'next_ns':START,'generation':2,'receipts':1}
        published=lambda mode:{'result':{'status':'PUBLISHED','mode':mode}}
        self.assertTrue(evaluate(before,{'next_ns':START+FIVE_NS,'generation':3,'receipts':2},published('forward')))
        self.assertTrue(evaluate(before,{'next_ns':START,'generation':3,'receipts':2},published('recheck')))
        self.assertFalse(evaluate(before,before,published('forward')))
        self.assertTrue(evaluate(before,dict(before),{'result':{'status':'RETRY_PENDING'}}))
        self.assertFalse(evaluate(before,{'next_ns':START+FIVE_NS,'generation':3,'receipts':2},
                                  {'result':{'status':'RETRY_PENDING'}}))


if __name__ == '__main__':
    unittest.main()
