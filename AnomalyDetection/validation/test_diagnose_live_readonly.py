"""Privacy, isolation and failure independence of the optional live probe."""
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('live_probe',Path(__file__).with_name('diagnose_live_readonly.py'))
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)


class ReadOnlyProbeTests(unittest.TestCase):
    def test_unreadable_source_identifies_only_the_relative_file_and_keeps_pg_samples(self):
        with tempfile.TemporaryDirectory() as temp:
            project=Path(temp).resolve(); calls=[]
            def source(path):
                raise PermissionError(13,'password=must-not-appear',str(project/'catalogs/fixture.json'))
            @contextmanager
            def database(root,*,readonly):
                calls.append((root,readonly))
                class Raw:
                    def execute(self,sql):
                        self.asserted_sql=sql
                        return self
                    def fetchall(self):
                        return [{'pid':7,'wait_event_type':'Lock','wait_event':'transactionid','statement_class':'OWNED_HISTORY'}]
                yield Raw()
            value=probe.collect(project,source_identity=source,status=lambda root:{'health':'RUNNING'},database=database,wait=lambda _:None)
            self.assertEqual(value['source_check']['status'],'READ_FAILED')
            self.assertEqual(value['source_check']['failure']['file'],'catalogs/fixture.json')
            self.assertEqual(len(calls),2)
            self.assertTrue(all(readonly for root,readonly in calls))
            self.assertTrue(all(s['own_postgresql_activity']['status']=='READ' for s in value['samples']))
            self.assertNotIn('must-not-appear',json.dumps(value))
            self.assertNotIn(temp,json.dumps(value))
            self.assertFalse(value['database_modified'])

    def test_database_failure_does_not_hide_a_valid_source_identity_or_worker(self):
        class Cancelled(Exception):sqlstate='57014'
        @contextmanager
        def database(*args,**kwargs):
            raise Cancelled('credential-never-export')
            yield
        value=probe.collect(Path.cwd(),source_identity=lambda _: {'runtime_sha256':'fixture'},status=lambda _: {'health':'RUNNING'},database=database,wait=lambda _:None)
        self.assertEqual(value['source_check']['status'],'READ')
        self.assertTrue(all(s['worker']['status']=='READ' for s in value['samples']))
        self.assertEqual(value['samples'][0]['own_postgresql_activity']['failure']['sqlstate'],'57014')
        self.assertNotIn('credential-never-export',json.dumps(value))

    def test_process_summary_omits_owner_capabilities_and_unneeded_target_identity(self):
        status={'process':{'locked':True,'owner':{'pid':7,'instance_token':'private-capability','command':'private-command'}},
            'worker':{'phase':'evaluate_history','evaluating_target':{'session_key':'private-session'},'unknown_field':'private-value'}}
        value=probe.process_summary(status)
        self.assertEqual(value['process']['owner']['pid'],7)
        self.assertEqual(value['worker']['phase'],'evaluate_history')
        self.assertNotIn('private-',json.dumps(value))

    def test_activity_statement_is_a_bounded_select_of_only_the_current_ad_role(self):
        sql=probe.ACTIVITY_SQL
        self.assertTrue(sql.lstrip().startswith('SELECT '))
        self.assertIn('usename=current_user',sql)
        self.assertIn('datname=current_database()',sql)
        self.assertIn('pid<>pg_backend_pid()',sql)
        self.assertIn('LIMIT 32',sql)
        self.assertNotIn('query AS',sql)
        self.assertNotIn('SELECT *',sql)


if __name__=='__main__':unittest.main()
