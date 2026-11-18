"""Safety and exact bounded job reads; native cases use disposable PG only."""
from contextlib import nullcontext
import json
import os
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

from validation import focused_diagnostics as diag


class DiagnosticTests(unittest.TestCase):
    def test_trace_reports_code_site_without_message_source_or_locals(self):
        project=Path('/synthetic-project')
        code=compile("def fail():\n value=None\n return value.nonexistent_secret('PRIVATE_PASSWORD_AND_SQL')\nfail()",str(project/'p24_foundation/service_journey.py'),'exec')
        try:
            exec(code,{})
        except AttributeError as exc:
            value=diag.problem(exc,project)
        self.assertEqual(value['error_type'],'AttributeError')
        self.assertTrue(value['sites'])
        self.assertEqual(value['sites'][-1]['function'],'fail')
        self.assertNotIn('PRIVATE',json.dumps(value))
        self.assertNotIn('nonexistent_secret',json.dumps(value))
        self.assertNotIn(str(project),json.dumps(value))

    def test_deadline_preserves_unknown_without_touching_database(self):
        raw=SimpleNamespace(execute=lambda *a: self.fail('deadline must precede SQL'))
        value=diag.case_jobs(raw,0,clock=lambda:1)
        self.assertFalse(value['complete'])
        self.assertEqual(value['error']['error_type'],'OBSERVATION_DEADLINE')

    def test_timeout_is_partial_without_query_or_secret(self):
        class Canceled(Exception):sqlstate='57014'
        def fail(*args):raise Canceled('PRIVATE_QUERY_AND_PASSWORD')
        raw=SimpleNamespace(transaction=nullcontext,execute=fail)
        value=diag.case_jobs(raw,2,clock=lambda:1)
        self.assertFalse(value['complete'])
        self.assertEqual(value['error']['sqlstate'],'57014')
        self.assertNotIn('PRIVATE',json.dumps(value))

    def test_journey_probes_are_bounded_and_never_export_packet_payloads(self):
        source=SimpleNamespace(project=Path('/synthetic-project'))
        calls=[]
        def read(source,key):
            calls.append(key)
            if key=='2':raise AttributeError('PRIVATE_DETAILS')
            return {'semantic':{},'journey':{'PRIVATE_PAYLOAD':True},'payment':None,'service_context':None}
        value=diag.journey_probes(source,['1','2','3','4'],2,clock=lambda:1,read=read)
        self.assertEqual(calls,['1','2','3'])
        self.assertEqual([r['status'] for r in value],['READ_MODELS_COMPLETED','READ_MODELS_FAILED','READ_MODELS_COMPLETED'])
        self.assertNotIn('PRIVATE',json.dumps(value))


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native disposable cluster not configured')
class NativeFocusedReads(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_scenario_invalidation_pg import NativeScenarioInvalidationTests
        NativeScenarioInvalidationTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):cls.admin.close()

    def setUp(self):
        from tests.test_scenario_invalidation_pg import NativeScenarioInvalidationTests
        NativeScenarioInvalidationTests.setUp(self)

    def seed(self,n=33):
        for i in range(n):
            session=f's-{i:04}';target=1000+i
            self.raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,evaluation) VALUES(%s,%s,%s)',
                (session,target,json.dumps({'decisions':[{'family':'fixture','status':'INSUFFICIENT_DATA'}]})))
            self.raw.execute('INSERT INTO anomaly_detection.adp_case_signals('
                'signal_key,case_key,scope_key,job_session,target_ns,job_version,source_kind,family,state,qualified,'
                'review_eligible,begin_ns,end_ns,score,body,content_digest,updated_ns) '
                "VALUES(%s,'case','scope',%s,%s,1,'actor','fixture','ACTIVE',FALSE,FALSE,1,2,0,'{}','digest',1)",
                (f'signal-{i}',session,target))

    def test_complete_point_reads_equal_job_rows_under_enforced_read_only(self):
        self.seed()
        with self.raw.transaction():
            self.raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            value=diag.case_jobs(self.raw,time.monotonic()+10)
            self.assertTrue(value['complete'])
            self.assertEqual(len(value['rows']),33)
            self.assertEqual(value['missing_job_keys'],[])
            for row in value['rows']:
                expected=dict(self.raw.execute('SELECT '+','.join(row)+' FROM anomaly_detection.adp_jobs '
                    'WHERE session_key=%s AND target_ns=%s',(row['session_key'],row['target_ns'])).fetchone())
                self.assertEqual(row,expected)
            with self.assertRaises(self.psycopg.errors.ReadOnlySqlTransaction):
                with self.raw.transaction():
                    self.raw.execute('UPDATE anomaly_detection.adp_jobs SET version=version+1')
        self.assertEqual(self.raw.execute('SELECT MAX(version) AS v FROM anomaly_detection.adp_jobs').fetchone()['v'],1)

    def test_scope_overflow_is_explicit_not_a_complete_truncated_export(self):
        self.seed()
        with patch.object(diag,'MAX_SCOPES',32):
            value=diag.case_jobs(self.raw,time.monotonic()+10)
        self.assertFalse(value['complete'])
        self.assertEqual(len(value['rows']),32)
        self.assertEqual(value['error']['error_type'],'CASE_SCOPE_BUDGET_EXCEEDED')

    def test_byte_budget_does_not_claim_complete_even_with_successful_sql(self):
        self.seed(1)
        with patch.object(diag,'MAX_BYTES',8):
            value=diag.case_jobs(self.raw,time.monotonic()+10)
        self.assertFalse(value['complete'])
        self.assertEqual(value['error']['error_type'],'DATASET_BYTE_BUDGET')

    def test_real_timeout_keeps_the_successful_prefix_and_parent_snapshot_usable(self):
        self.seed()
        raw=self.raw
        class Proxy:
            transaction=raw.transaction
            batches=0
            def execute(self,sql,args=()):
                if sql.startswith('SELECT j.session_key'):
                    self.batches+=1
                    if self.batches==2:
                        raw.execute('SELECT pg_sleep(0.1)')
                return raw.execute(sql,args)
        with self.raw.transaction():
            self.raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            self.raw.execute("SET LOCAL statement_timeout='40ms'")
            value=diag.case_jobs(Proxy(),time.monotonic()+10)
            self.assertFalse(value['complete'])
            self.assertEqual(value['error']['sqlstate'],'57014')
            self.assertEqual(len(value['rows']),diag.BATCH)
            self.assertEqual(self.raw.execute('SELECT 1 AS ok').fetchone()['ok'],1)

    def test_repeatable_read_keeps_metadata_from_before_concurrent_version_update(self):
        self.seed(3)
        other=self.psycopg.connect(**self.params,dbname=self.name,autocommit=True)
        self.addCleanup(other.close)
        raw=self.raw
        class Proxy:
            transaction=raw.transaction
            changed=False
            def execute(self,sql,args=()):
                if sql.startswith('SELECT j.session_key') and not self.changed:
                    self.changed=True
                    other.execute('UPDATE anomaly_detection.adp_jobs SET version=version+1')
                return raw.execute(sql,args)
        with self.raw.transaction():
            self.raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            value=diag.case_jobs(Proxy(),time.monotonic()+10)
            self.assertTrue(value['complete'])
            self.assertEqual({row['version'] for row in value['rows']},{1})
        self.assertEqual(self.raw.execute('SELECT MAX(version) AS v FROM anomaly_detection.adp_jobs').fetchone()['v'],2)


if __name__=='__main__':unittest.main()
