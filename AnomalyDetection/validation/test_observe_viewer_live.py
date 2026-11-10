"""Read-only isolation, privacy and honest capacity calculations for live probe."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('viewer_observer', Path(__file__).with_name('observe_viewer_live.py'))
probe = importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)


def receipt(window, published_seconds, *, elapsed=475):
    return {'start_ns': window * probe.FIVE_NS, 'end_ns': (window + 1) * probe.FIVE_NS,
        'mode': 'forward', 'published_ns': int(published_seconds * probe.SECOND_NS),
        'elapsed_seconds': elapsed, 'capture_seconds': 9}


class Clock:
    def __init__(self): self.now = 0
    def read(self): return self.now
    def wait(self, seconds): self.now += seconds


class FakeReader:
    def __init__(self, *, fail_tables=False, writable=False):
        self.statements = []; self.fail_tables = fail_tables; self.writable = writable

    def rows(self, sql, parameters=()):
        self.statements.append(sql)
        if sql.startswith('SELECT current_database()'):
            return [{'database': 'p24_design_viewer', 'read_only': 'off' if self.writable else 'on'}]
        if sql == probe.TABLES_SQL and self.fail_tables:
            raise PermissionError('password=never-export')
        if sql == probe.STATE_SQL:
            return [{'start_ns': 0, 'next_ns': probe.FIVE_NS, 'generation': 8,
                'lag_seconds': 60, 'worker_status': 'published'}]
        if sql == probe.ACTIVITY_SQL:
            return [{'pid': 7, 'state': 'active', 'application_name': 'password=never-export',
                'query': "SELECT * FROM public.viewer_events WHERE request_key='private-request'",
                'viewer_singleton_owner': True, 'wait_event_type': 'IO', 'wait_event': 'DataFileRead'}]
        if sql == probe.RECEIPTS_SQL:
            return [receipt(0, 475), receipt(1, 950)]
        return []

    def optional(self, sql, parameters=()):
        return probe.attempt(lambda: self.rows(sql, parameters))


class ViewerObservationTests(unittest.TestCase):
    def test_connection_overrides_private_writable_options_and_rejects_other_db(self):
        options = probe.connection_parameters({'dbname': 'p24_design_viewer', 'password': 'secret',
            'options': '-c default_transaction_read_only=off', 'application_name': 'private'})
        self.assertIn('default_transaction_read_only=on', options['options'])
        self.assertNotIn('default_transaction_read_only=off', options['options'])
        self.assertIn('statement_timeout=2000', options['options'])
        self.assertEqual(options['application_name'], probe.APP)
        with self.assertRaises(ValueError): probe.connection_parameters({'dbname': 'production'})

    def test_reader_rejects_mutations_before_opening_cursor(self):
        class Connection:
            def cursor(self): raise AssertionError('mutation reached driver')
        reader = probe.Reader(Connection())
        for sql in ('UPDATE viewer_live_state SET next_ns=0', 'ANALYZE viewer_events',
                    'EXPLAIN ANALYZE SELECT 1', 'SET default_transaction_read_only=off'):
            with self.assertRaises(ValueError): reader.rows(sql)

    def test_failed_read_only_guard_stops_before_collecting(self):
        reader = FakeReader(writable=True)
        with self.assertRaises(ValueError):
            probe.collect(reader, seconds=3, allowed_names=set())
        self.assertEqual(len(reader.statements), 1)

    def test_source_inventory_uses_runtime_byte_definition_and_exports_no_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'p24_foundation').mkdir()
            (root / 'p24_foundation/viewer_data.py').write_bytes(b"# private-source\nTABLE='viewer_events'\r\n")
            (root / 'tools').mkdir(); (root / 'tools/tool.py').write_bytes(b'TABLE="viewer_requests"\n')
            value, names = probe.source_inventory(root)
            import hashlib
            expected = hashlib.sha256()
            for rel in ('p24_foundation/viewer_data.py', 'tools/tool.py'):
                expected.update(rel.encode() + b'\0'); expected.update(hashlib.sha256((root / rel).read_bytes()).digest())
            self.assertEqual(value['runtime_sha256'], expected.hexdigest())
            self.assertEqual(value['runtime_files'], 2)
            self.assertTrue({'viewer_events', 'viewer_requests', 'viewer_stage_events',
                'viewer_build_requests'}.issubset(names))
            self.assertNotIn('private-source', json.dumps(value))

    def test_activity_omits_query_application_literals_and_idle_last_statement(self):
        allowed = {'viewer_events'}
        rows = [{'pid': 1, 'state': 'active', 'viewer_singleton_owner': True,
            'application_name': 'credential-do-not-export',
            'query': "SELECT * FROM viewer_events WHERE request_key='request-secret' /* viewer_privateuser */"},
            {'pid': 2, 'state': 'idle', 'application_name': 'AnomalyDetection.Product.worker',
             'query': 'DELETE FROM viewer_events'}]
        result = probe.activity_rows(rows, allowed)
        serialized = json.dumps(result)
        for secret in ('credential-do-not-export', 'request-secret', 'viewer_privateuser', 'SELECT *', 'DELETE FROM'):
            self.assertNotIn(secret, serialized)
        self.assertEqual(result['sessions'][0]['statement']['relations'], ['viewer_events'])
        self.assertNotIn('statement', result['sessions'][1])
        self.assertEqual(result['sessions'][1]['workload'], 'AD')
        self.assertEqual(probe.statement_summary("SELECT 1 FROM viewer_events WHERE request_key='a'", allowed),
                         probe.statement_summary("SELECT 2 FROM viewer_events WHERE request_key='b'", allowed))

    def test_475_second_publisher_cannot_reduce_a_continuing_backlog(self):
        result = probe.receipt_summary([receipt(i, (i + 1) * 475) for i in range(4)], 11461)
        self.assertEqual(result['throughput_status'], 'HISTORICAL_SAMPLE_CANNOT_CATCH_UP')
        self.assertAlmostEqual(result['observed_forward_windows_per_hour'], 3600 / 475, places=3)
        self.assertLess(result['net_catchup_windows_per_hour'], 0)
        self.assertIsNone(result['estimated_catchup_hours'])

    def test_catchup_estimate_subtracts_incoming_windows(self):
        result = probe.receipt_summary([receipt(i, (i + 1) * 225, elapsed=200) for i in range(4)], 11461)
        self.assertEqual(result['observed_forward_windows_per_hour'], 16)
        self.assertEqual(result['net_catchup_windows_per_hour'], 4)
        self.assertEqual(result['estimated_catchup_hours'], 2865.25)

    def test_gap_or_duplicate_cannot_fabricate_capacity(self):
        self.assertEqual(probe.receipt_summary([receipt(0, 100), receipt(4, 200)])['throughput_status'], 'NONCONTIGUOUS_RECEIPTS')
        duplicate = probe.receipt_summary([receipt(0, 100), receipt(0, 200)])
        self.assertEqual(duplicate['sample_windows'], 1)
        self.assertEqual(duplicate['throughput_status'], 'INSUFFICIENT_RECEIPTS')
        self.assertEqual(probe.receipt_summary([receipt(0, 200), receipt(1, 100)])['throughput_status'], 'NONCONTIGUOUS_RECEIPTS')

    def test_empty_receipts_do_not_mean_stopped_or_normal(self):
        self.assertEqual(probe.receipt_summary([])['throughput_status'], 'INSUFFICIENT_RECEIPTS')

    def test_statistics_reset_is_not_negative_or_false_delta(self):
        before = {'database': {'status': 'READ', 'value': [{'stats_reset': 'a', 'blks_read': 20}]}}
        after = {'database': {'status': 'READ', 'value': [{'stats_reset': 'b', 'blks_read': 2}]}}
        self.assertEqual(probe.counter_deltas(before, after)['database'], {'status': 'STATS_RESET'})
        after['database']['value'][0]['stats_reset'] = 'a'
        self.assertIsNone(probe.counter_deltas(before, after)['database']['values']['blks_read'])

    def test_one_unavailable_dataset_does_not_hide_publisher_waits_or_other_evidence(self):
        reader = FakeReader(fail_tables=True); clock = Clock()
        value = probe.collect(reader, seconds=6, allowed_names={'viewer_events'},
            clock=clock.read, wall=lambda: 100 * probe.FIVE_NS, wait=clock.wait)
        self.assertEqual(len(value['samples']), 3)
        self.assertEqual(value['status'], 'PARTIAL_READ_ONLY_OBSERVATION')
        self.assertEqual(value['read_failures'], 1)
        self.assertEqual(value['publisher_observation']['active_wait_sample_counts'], {'IO/DataFileRead': 3})
        self.assertEqual(value['latest_viewer_state']['backlog_windows'], 98)
        self.assertFalse(value['checkpoint_seek_performed'])
        self.assertFalse(value['database_modified'])
        serialized = json.dumps(value)
        for secret in ('never-export', 'private-request', 'SELECT * FROM'):
            self.assertNotIn(secret, serialized)
        self.assertTrue(all(sql.startswith('SELECT ') for sql in reader.statements))


if __name__ == '__main__': unittest.main()
