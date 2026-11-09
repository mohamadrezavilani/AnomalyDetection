"""Historical boundary replay through the real maintained reconstruction."""
import copy
import gzip
import json
from pathlib import Path
import tempfile
import unittest

from p24_foundation.historical_replay import audit
from p24_foundation.errors import FoundationError
from tests.helpers import TEST_KEYS,document,fixture


class HistoricalReplayTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)

    def dump(self,name,rows,start,end):
        path=self.root/name
        with gzip.open(path,'wt',encoding='utf-8') as stream:
            json.dump(dict(window_start=start,window_end=end,logs=rows,count=len(rows),complete=True),stream,default=str)
        return path

    def boundary(self):
        rows=list(fixture('boundary.sanitized.json').records)
        from p24_foundation.parser import field
        from p24_foundation.time import parse_time
        left=[r for r in rows if parse_time(field(r,'@timestamp')[0]).epoch_ns<parse_time('2026-10-20T07:30:00Z').epoch_ns]
        right=[r for r in rows if r not in left]
        return [self.dump('left.json.gz',left,'2026-10-20T07:25:00Z','2026-10-20T07:30:00Z'),
                self.dump('right.json.gz',right,'2026-10-20T07:30:00Z','2026-10-20T07:35:00Z')]

    def test_real_sanitized_boundary_completes_once_and_retains_prior_unknown(self):
        report=audit(self.boundary(),keys=TEST_KEYS)
        self.assertEqual(report['input_records'],14)
        self.assertEqual(report['raw_request_ids'],1)
        self.assertEqual(report['cross_window_changes']['client_completion_arrived_later'],1)
        example=report['examples'][0]
        self.assertEqual((example['earlier_events'],example['combined_events']),(11,14))
        self.assertEqual((example['sql_observations'],example['provider_observations'],example['logical_client_requests']),(12,1,1))
        self.assertEqual((example['earlier_final_outcome'],example['combined_final_outcome']),('unknown','failure'))
        self.assertFalse(report['source_completeness_verified']);self.assertFalse(report['database_used'])

    def test_reversed_files_produce_same_semantics_and_duplicate_deliveries_are_tested(self):
        paths=self.boundary();first=audit(paths,keys=TEST_KEYS);second=audit(paths[::-1],keys=TEST_KEYS)
        for name in ['request_summary_counts','cross_window_changes','examples','selected_origins','checks']:
            self.assertEqual(first[name],second[name])
        self.assertEqual(first['checks']['duplicate_delivery'],1)

    def test_conflicting_origin_moving_requestid_stays_one_connected_ambiguity(self):
        first=document(rid='A',oid='same',at='2026-10-20T07:29:00Z')
        second=copy.deepcopy(first);second['_source']['RequestID']='B'
        paths=[self.dump('a.gz',[first],'2026-10-20T07:25:00Z','2026-10-20T07:30:00Z'),
               self.dump('b.gz',[second],'2026-10-20T07:30:00Z','2026-10-20T07:35:00Z')]
        result=audit(paths,keys=TEST_KEYS)
        self.assertEqual(result['ambiguous_origins'],1);self.assertEqual(result['selected_origins'],0)
        self.assertEqual(result['request_summary_counts']['reconstructed_request_ids'],2)

    def test_duplicate_input_and_aggregate_limit_fail_explicitly(self):
        paths=self.boundary()
        with self.assertRaisesRegex(FoundationError,'historical_duplicate_input'):audit([paths[0],paths[0]],keys=TEST_KEYS)
        with self.assertRaisesRegex(FoundationError,'historical_total_record_limit'):audit(paths,keys=TEST_KEYS,max_total_records=1)

    def test_report_contains_no_raw_request_session_ip_or_messages(self):
        row=document(rid='PRIVATE_REQUEST',session='PRIVATE_SESSION',ip='192.0.2.55',oid='PRIVATE_ORIGIN',at='2026-10-20T07:29:00Z')
        result=audit([self.dump('privacy.gz',[row],'2026-10-20T07:25:00Z','2026-10-20T07:30:00Z')],keys=TEST_KEYS)
        raw=json.dumps(result)
        for secret in ['PRIVATE_REQUEST','PRIVATE_SESSION','192.0.2.55','PRIVATE_ORIGIN']:self.assertNotIn(secret,raw)

    def test_future_only_origin_is_explicitly_excluded_and_single_file_is_not_cross_window(self):
        row=document(rid='FUTURE',oid='future',at='2026-10-20T07:31:00Z')
        result=audit([self.dump('future.gz',[row],'2026-10-20T07:25:00Z','2026-10-20T07:30:00Z')],keys=TEST_KEYS)
        self.assertEqual(result['unique_input_origins'],1)
        self.assertEqual(result['excluded_future_origins'],1)
        self.assertEqual(result['selected_origins'],0)
        self.assertEqual(result['raw_request_ids_in_every_input'],0)
        self.assertEqual(result['cross_window_changes'],{})
