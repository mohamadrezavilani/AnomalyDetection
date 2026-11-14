"""Read-only isolation, privacy and honest capacity calculations for live probe."""
import importlib.util
import copy
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


def fresh_snapshot(count=0, **changes):
    rows = [dict(start_ns=(i+1)*probe.FIVE_NS, end_ns=(i+2)*probe.FIVE_NS,
        generation=9+i, published_ns=100-i) for i in range(count)]
    value = dict(stream_key='private-stream', keys_fingerprint='private-keys', start_ns=0,
        next_ns=(count+1)*probe.FIVE_NS, generation=8+count, server_started='boot-1',
        publishers=[{'pid': 7, 'backend_start': 'worker-1'}], receipts=rows)
    value.update(changes)
    return {'status': 'READ', 'value': [value]}


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
        if sql == probe.FRESH_SQL:
            return fresh_snapshot()['value']
        return []

    def optional(self, sql, parameters=()):
        return probe.attempt(lambda: self.rows(sql, parameters))


class ViewerObservationTests(unittest.TestCase):
    def test_history_progress_separates_verified_skips_from_actual_publication(self):
        base=dict(run_id='one',from_ns=0,next_ns=2*probe.FIVE_NS,end_ns=100*probe.FIVE_NS,
            skipped_windows=2,published_windows=0,status='RUNNING',ad_prepared=0,ad_started=0)
        after={**base,'next_ns':82*probe.FIVE_NS,'skipped_windows':80,'published_windows':2}
        summary=probe.replay_progress({'status':'READ','value':[base]},{'status':'READ','value':[after]})
        self.assertEqual(summary['remaining_windows'],18)
        self.assertEqual(summary['new_missing_windows_published_during_observation'],2)
        self.assertEqual(summary['complete_windows_skipped_during_observation'],78)
        self.assertTrue(summary['forward_publication_paused_for_history_replay'])
        self.assertNotIn('observed_forward_windows_per_hour',summary)
        self.assertEqual(probe.replay_snapshot(FakeReader()),{'status':'NOT_SCHEDULED'})
        changed={**after,'run_id':'another'}
        summary=probe.replay_progress({'status':'READ','value':[base]},{'status':'READ','value':[changed]})
        self.assertNotIn('new_missing_windows_published_during_observation',summary)

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

    def test_source_inventory_normalizes_the_project_alias_before_checking_containment(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'p24_foundation').mkdir();(root/'alias').mkdir()
            (root/'p24_foundation/viewer_data.py').write_bytes(b'TABLE="viewer_events"\n')
            self.assertEqual(probe.source_inventory(root/'alias'/'..'),probe.source_inventory(root.resolve()))

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
        self.assertEqual(value['throughput']['throughput_status'], 'INSUFFICIENT_FRESH_COMMITS')
        self.assertNotIn('observed_forward_windows_per_hour', value['throughput'])
        self.assertEqual(value['historical_throughput']['sample_windows'], 2)
        serialized = json.dumps(value)
        for secret in ('never-export', 'private-request', 'SELECT * FROM'):
            self.assertNotIn(secret, serialized)
        self.assertTrue(all(sql.startswith('SELECT ') for sql in reader.statements))

    def test_collect_stops_on_two_fresh_commits_without_using_old_receipts(self):
        class PublishingReader(FakeReader):
            calls = 0
            def rows(self, sql, parameters=()):
                if sql == probe.FRESH_SQL:
                    self.statements.append(sql)
                    result = fresh_snapshot(self.calls)['value']
                    self.calls += 1
                    return result
                return super().rows(sql, parameters)
        reader = PublishingReader(); clock = Clock(); messages = []
        value = probe.collect(reader, seconds=1800, forward_windows=2, allowed_names=set(),
            clock=clock.read, wall=lambda: 1, wait=clock.wait, progress=messages.append)
        self.assertEqual(clock.now, 6)
        self.assertEqual(value['measurement_stop_reason'], 'TARGET_FRESH_WINDOWS_OBSERVED')
        self.assertEqual(value['throughput']['sample_windows'], 2)
        self.assertEqual(value['throughput']['observed_forward_windows_per_hour'], 1200)
        self.assertFalse(value['throughput']['historical_receipts_used'])


class FreshForwardTests(unittest.TestCase):
    def setUp(self):
        self.fresh = probe.FreshForward()
        self.observe(fresh_snapshot(), 0)

    def observe(self, result, started, finished=None):
        self.fresh.observe(result, started=started, finished=started if finished is None else finished,
            observed_ns=int(started*probe.SECOND_NS))

    def test_only_intervals_between_new_commits_count_and_wall_times_do_not_set_rate(self):
        # Receipt timestamps deliberately go backwards; the publisher's old
        # 475-second timers and the first partial cycle cannot set fresh rate.
        self.observe(fresh_snapshot(1), 100)
        self.observe(fresh_snapshot(2), 300)
        result = self.fresh.summary(300)
        self.assertEqual(result['observed_forward_windows_per_hour'], 18)
        self.assertEqual(result['interval_seconds_min'], 0)
        self.assertEqual(result['interval_seconds_max'], 300)
        self.assertTrue(result['first_completion_excluded_from_cycle_timing'])
        self.assertNotIn('private-stream', json.dumps(result))
        self.assertNotIn('private-keys', json.dumps(result))

    def test_polling_bounds_enclose_commit_latency_instead_of_publisher_precommit_timer(self):
        self.observe(fresh_snapshot(), 97, 98)
        self.observe(fresh_snapshot(1), 100, 101)
        self.observe(fresh_snapshot(1), 297, 298)
        self.observe(fresh_snapshot(2), 300, 301)
        result = self.fresh.summary(301)
        self.assertEqual(result['interval_seconds_min'], 196)
        self.assertEqual(result['interval_seconds_max'], 204)
        self.assertEqual(result['throughput_status'], 'FRESH_SAMPLE_EXCEEDS_ARRIVAL')
        self.assertLess(result['windows_per_hour_min'], 18)
        self.assertGreater(result['windows_per_hour_max'], 18)

    def test_rechecks_and_repeated_polls_do_not_count_as_forward_progress(self):
        self.observe(fresh_snapshot(generation=9), 3)
        value = fresh_snapshot(1, generation=10)
        value['value'][0]['receipts'][0]['generation'] = 10
        self.observe(value, 6)
        value = copy.deepcopy(value); value['value'][0]['generation'] = 11
        self.observe(value, 9)
        self.assertEqual(self.fresh.summary(9)['sample_windows'], 1)
        self.assertEqual(self.fresh.summary(9)['throughput_status'], 'INSUFFICIENT_FRESH_COMMITS')

    def test_worker_restart_reboot_stream_change_or_cursor_regression_invalidate_rate(self):
        for changes in ({'publishers': [{'pid': 7, 'backend_start': 'reused-pid'}]},
                {'server_started': 'new-boot'}, {'stream_key': 'new-stream'},
                {'keys_fingerprint': 'new-keys'}, {'generation': 7}, {'next_ns': 0}):
            with self.subTest(changes=changes):
                self.setUp(); self.observe(fresh_snapshot(**changes), 3)
                result = self.fresh.summary(3)
                self.assertIn(result['throughput_status'], ('MEASUREMENT_EPOCH_CHANGED', 'SOURCE_CURSOR_REGRESSED'))
                self.assertNotIn('observed_forward_windows_per_hour', result)

    def test_seek_duplicate_missing_or_rewritten_receipts_do_not_fabricate_rate(self):
        for kind in ('seek', 'duplicate', 'missing', 'changed'):
            with self.subTest(kind=kind):
                self.setUp(); self.observe(fresh_snapshot(1), 3)
                value = fresh_snapshot(2)
                rows = value['value'][0]['receipts']
                if kind == 'seek': rows[1]['start_ns'] += probe.FIVE_NS
                if kind == 'duplicate': rows[1] = copy.deepcopy(rows[0])
                if kind == 'missing': del rows[1]
                if kind == 'changed': rows[0]['published_ns'] += 1
                self.observe(value, 6)
                self.assertIsNotNone(self.fresh.failure)
                self.assertNotIn('observed_forward_windows_per_hour', self.fresh.summary(6))

    def test_unavailable_reads_or_owner_never_claim_zero_throughput(self):
        for value in ({'status': 'READ_FAILED'}, {'status': 'READ', 'value': []},
                fresh_snapshot(publishers=[]), fresh_snapshot(publishers=[{'pid': 7, 'backend_start': None}])):
            with self.subTest(value=value):
                self.setUp(); self.observe(value, 3)
                self.assertIsNotNone(self.fresh.failure)
                self.assertNotIn('observed_forward_windows_per_hour', self.fresh.summary(3))

    def test_two_commits_in_one_poll_have_a_rate_bound_and_no_invented_point_estimate(self):
        self.observe(fresh_snapshot(2), 3)
        result = self.fresh.summary(3)
        self.assertIsNone(result['observed_forward_windows_per_hour'])
        self.assertEqual(result['windows_per_hour_min'], 1200)
        self.assertIsNone(result['windows_per_hour_max'])

    def test_receipt_overflow_invalidates_instead_of_reporting_a_partial_population(self):
        self.observe(fresh_snapshot(257), 3)
        self.assertEqual(self.fresh.summary(3)['throughput_status'], 'FRESH_RECEIPTS_TRUNCATED')


if __name__ == '__main__': unittest.main()
