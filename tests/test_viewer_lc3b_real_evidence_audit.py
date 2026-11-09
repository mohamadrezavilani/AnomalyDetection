"""LC3B: read-only witness of real-schema rows, not full R5 case acceptance."""
from __future__ import annotations
import gzip
from contextlib import closing
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from tools.run_lc3b_readmodel import execute_audit, main, read_options
from tests.test_viewer_r6_service_journey import log


class LC3BReadModelEvidenceTests(unittest.TestCase):
    def setUp(self):
        context=tempfile.TemporaryDirectory();self.addCleanup(context.cleanup)
        self.folder=Path(context.name)
        key_file=self.folder/'keys.json';generate_keys(key_file)
        self.db_path=self.folder/'isolated.sqlite'
        self.db=ViewerDB(sqlite_path=self.db_path,keys_path=key_file)
        self.addCleanup(self.db.close)
        self.db.init()
        self.config=self.folder/'viewer_config.local.py'
        self.config.write_text(f'SQLITE_OFFLINE_PATH = {str(self.db_path)!r}\n',encoding='utf-8')

    def ingest_file(self,filename,rows,start,end):
        location=self.folder/filename
        with gzip.open(location,'wt',encoding='utf8') as fd:
            json.dump({'window_start':start,'window_end':end,'count':len(rows),'logs':rows},fd)
        result=self.db.ingest([location])
        self.assertEqual('IMPORTED',result[0]['status'])
        self.db.rebuild()
        self.db.rebuild_payment_contract()
        return location

    def two_windows(self):
        before=log(1,'shared','Services.v1/TrafficFinesCarNoDetails Line:302',
                   'POST (G00000 | successful)',second=1)
        before['@timestamp']='2026-10-24T04:19:59Z'
        after=log(2,'shared','DBPath.application.ud_prc_invoiceInfo',
                  'POST (G00000 | successful)',second=2)
        after['@timestamp']='2026-10-24T04:20:01Z'
        self.ingest_file('first.json.gz',[before],
                         '2026-10-24T04:15:00Z','2026-10-24T04:20:00Z')
        second=self.ingest_file('next.json.gz',[after],
                         '2026-10-24T04:20:00Z','2026-10-24T04:25:00Z')
        return second

    def test_real_schema_cross_window_witness_and_provisional_status(self):
        self.two_windows()
        evidence=execute_audit(self.config)
        self.assertEqual(1,evidence['counts']['indexed_requests'])
        self.assertEqual(1,evidence['counts']['five_minute_spanning_requests'])
        self.assertEqual(1,evidence['counts']['five_minute_spanning_service_requests'])
        sample=evidence['sampled_cross_window_service_requests']
        self.assertEqual(1,len(sample))
        self.assertEqual(2,sample[0]['evidence']['distinct_source_files_sampled'])
        self.assertEqual(2,sample[0]['evidence']['distinct_declared_export_windows_sampled'])
        self.assertEqual(2,sample[0]['evidence']['distinct_five_minute_time_buckets_sampled'])
        self.assertEqual('different_declared_export_windows_and_time_buckets_observed',sample[0]['cross_window_observation'])
        self.assertEqual('service_execution',sample[0]['semantic_kind'])
        self.assertTrue(sample[0]['occurrence_key'].startswith('bo1:'))
        self.assertEqual('NOT_EXECUTED',sample[0]['full_r5_scenario_acceptance'])
        self.assertEqual(0,evidence['witness_assessment']['fully_accepted_end_to_end_cases'])


    def test_postgres_style_placeholder_compatibility_of_all_audit_queries(self):
        """A PG-format validator rejects raw % inside quoted LIKE fragments.

        Previously the local SQLite tests passed but psycopg3 rejected the two
        literal Services.v% queries before they ever reached PostgreSQL.
        """
        self.two_windows()
        from p24_foundation.lc3_readmodel_audit import audit
        from tools.run_lc3b_readmodel import ReadOnlyDB

        class StrictPsycopgStyleConnection:
            def __init__(self, handle):
                self.handle = handle

            def execute(self, statement, params=()):
                result = []
                i = 0
                slots = 0
                while i < len(statement):
                    if statement[i] != '%':
                        result.append(statement[i])
                        i += 1
                        continue
                    if i + 1 >= len(statement):
                        raise AssertionError('invalid_percent_marker')
                    marker = statement[i + 1]
                    if marker == 's':
                        result.append('?')
                        slots += 1
                    elif marker == '%':
                        result.append('%')
                    else:
                        raise AssertionError('invalid_psycopg_percent_placeholder')
                    i += 2
                if slots != len(params):
                    raise AssertionError('psycopg_parameter_count_mismatch')
                return self.handle.execute(''.join(result), params)

        with closing(sqlite3.connect(self.db_path)) as raw:
            raw.row_factory = sqlite3.Row
            simulated_pg = ReadOnlyDB(StrictPsycopgStyleConnection(raw), postgres=True)
            audited = audit(simulated_pg, sample_limit=1)
        self.assertEqual(1, audited['counts']['five_minute_spanning_service_requests'])
        self.assertEqual('service_execution', audited['sampled_cross_window_service_requests'][0]['semantic_kind'])

    def test_repeat_import_no_additional_occurrence_or_source_file(self):
        second=self.two_windows()
        first=execute_audit(self.config)['sampled_cross_window_service_requests'][0]
        again=self.db.ingest([second]);self.db.rebuild();self.db.rebuild_payment_contract()
        self.assertEqual('ALREADY_IMPORTED',again[0]['status'])
        next_one=execute_audit(self.config)['sampled_cross_window_service_requests'][0]
        self.assertEqual(first['occurrence_key'],next_one['occurrence_key'])
        self.assertEqual(first['evidence']['distinct_event_origins_sampled'],next_one['evidence']['distinct_event_origins_sampled'])
        self.assertEqual(first['evidence']['distinct_source_files_sampled'],next_one['evidence']['distinct_source_files_sampled'])
        # A repeat import witness is narrower than full N28 financial assertion.
        self.assertEqual('PARTIAL_INDEXED_EVIDENCE_ONLY',execute_audit(self.config)['witness_assessment']['N28']['status'])

    def test_audit_does_not_mutate_isolated_sqlite_and_rejects_writes(self):
        self.two_windows()
        before=self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n']
        answer=execute_audit(self.config)
        self.assertTrue(answer['read_only'])
        self.assertEqual(before,self.db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'])
        # A directly opened read-only SQLite handle must not allow writes.
        uri=self.db_path.as_uri()+'?mode=ro'
        with closing(sqlite3.connect(uri,uri=True)) as conn:
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute('DELETE FROM viewer_requests')

    def test_audit_fails_closed_on_wrong_database_and_config(self):
        for bad in ('pishkhan24_shadow','production','p24_design_','p24_design_foo-bad'):
            path=self.folder/('config_'+bad+'.py')
            path.write_text('DATABASE = '+repr({'dbname':bad})+'\n',encoding='utf-8')
            with self.subTest(bad=bad),self.assertRaises(ValueError):read_options(path)
        missing=self.folder/'missing_config.py'
        with self.assertRaises(ValueError):read_options(missing)

    def test_cross_bucket_without_two_imports_does_not_claim_multi_file(self):
        before=log(1,'same','Services.v1/TrafficFinesCarNoDetails Line:5',
                   'POST (G00000 | successful)')
        before['@timestamp']='2026-10-24T04:19:59Z'
        after=log(2,'same','DBPath.application.ud_prc_invoiceInfo',
                  'POST (G00000 | successful)')
        after['@timestamp']='2026-10-24T04:20:01Z'
        self.ingest_file('combined.json.gz',[before,after],
                         '2026-10-24T04:15:00Z','2026-10-24T04:25:00Z')
        witness=execute_audit(self.config)['sampled_cross_window_service_requests'][0]
        self.assertEqual('event_time_span_observed_but_distinct_export_windows_unverified',witness['cross_window_observation'])
        self.assertEqual(1,witness['evidence']['distinct_source_files_sampled'])

    def test_empty_samples_do_not_imply_all_behavior_absent(self):
        data=execute_audit(self.config)
        self.assertEqual([],data['sampled_cross_window_service_requests'])
        self.assertEqual('NO_SAMPLE_IN_CAPTURE',data['witness_assessment']['N29']['status'])
        self.assertEqual(0,data['witness_assessment']['fully_accepted_end_to_end_cases'])

    def test_command_produces_json_without_full_acceptance_claims(self):
        self.two_windows()
        output=self.folder/'report.json'
        self.assertEqual(0,main(['--config',str(self.config),'--out',str(output),'--sample-limit','3']))
        data=json.loads(output.read_text(encoding='utf-8'))
        self.assertEqual(0,data['witness_assessment']['fully_accepted_end_to_end_cases'])
        self.assertTrue(all(x['full_r5_scenario_acceptance']=='NOT_EXECUTED' for x in data['sampled_cross_window_service_requests']))


    def test_database_failure_diagnostic_is_staged_and_does_not_leak_secrets(self):
        from tools.run_lc3b_readmodel import ReadOnlyDB, ReadModelQueryError
        class DatabaseFailure(Exception):
            sqlstate = '42601'
        class FaultyConnection:
            def execute(self, statement, params=()):
                raise DatabaseFailure('password=do_not_print query=private_data')
        with self.assertRaises(ReadModelQueryError) as result:
            ReadOnlyDB(FaultyConnection(), postgres=True).one('SELECT * FROM viewer_requests')
        error = result.exception
        self.assertEqual('request_inventory', error.stage)
        self.assertEqual('42601', error.sqlstate)
        self.assertNotIn('do_not_print', str(error))

    def test_sample_limit_validation(self):
        self.assertEqual(2,main(['--config',str(self.config),'--out',str(self.folder/'bad.json'),'--sample-limit','21']))
        self.assertFalse((self.folder/'bad.json').exists())


if __name__=='__main__':unittest.main()
