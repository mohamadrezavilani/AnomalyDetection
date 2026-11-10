import json
import unittest
from anomaly_detection.owned_sql import ObservedConnection


class TraceTests(unittest.TestCase):
    def test_arguments_and_result_are_preserved_but_credentials_and_sql_are_not_exported(self):
        result=object();calls=[]
        class Raw:
            def execute(self,*args):calls.append(args);return result
        raw=Raw();observed=ObservedConnection(raw)
        query='SELECT secret_column FROM private_table WHERE token=%s';args=('credential-never-export',)
        self.assertIs(observed.execute(query,args),result)
        self.assertEqual(calls,[(query,args)])
        exported=json.dumps(observed.metrics())
        for secret in ('secret_column','private_table','credential-never-export','token'):
            self.assertNotIn(secret,exported)

    def test_original_exception_survives_and_connection_remains_usable(self):
        class Cancelled(Exception):sqlstate='57014'
        failure=Cancelled('private exception text')
        class Raw:
            def execute(self,query,args):
                if query=='FAIL':raise failure
                return 42
        observed=ObservedConnection(Raw())
        with self.assertRaises(Cancelled) as caught:observed.execute('FAIL')
        self.assertIs(caught.exception,failure)
        self.assertEqual(observed.metrics()[-1]['sqlstate'],'57014')
        self.assertEqual(observed.execute('SELECT 42'),42)
        self.assertIsNone(observed.metrics()[-1]['sqlstate'])

    def test_trace_is_bounded_and_diagnostics_do_not_render_composed_queries(self):
        class Raw:
            def execute(self,*_):return 7
        class Composed:
            def as_string(self):raise AssertionError('do not render composed values')
        observed=ObservedConnection(Raw())
        for _ in range(100):observed.execute('SELECT 7')
        self.assertEqual(len(observed.metrics()),16)
        self.assertEqual(observed.execute(Composed()),7)
        self.assertEqual(observed.metrics()[-1]['operation'],'COMPOSED')

    def test_progress_identifies_real_statement_boundaries_without_sql_or_parameters(self):
        events=[]
        class Raw:
            def execute(self,query,args):
                self.entered_with_active=events[-1]['active']
                return 42
        raw=Raw();observed=ObservedConnection(raw,observer=events.append)
        self.assertEqual(observed.execute('SELECT private_column WHERE password=%s',('private-password',)),42)
        self.assertTrue(raw.entered_with_active)
        self.assertEqual([r['active'] for r in events],[True,False])
        self.assertEqual(events[0]['statement_id'],events[1]['statement_id'])
        self.assertEqual(events[1]['operation'],'SELECT')
        self.assertNotIn('private',json.dumps(events))
        self.assertNotIn('password',json.dumps(events))

    def test_failed_progress_publication_cannot_change_a_sql_result_or_error(self):
        class Cancelled(Exception):sqlstate='57014'
        error=Cancelled('private-error-text')
        class Raw:
            def execute(self,query,args):
                if query=='FAIL':raise error
                return 42
        def observer(_):raise PermissionError('telemetry file unavailable')
        observed=ObservedConnection(Raw(),observer=observer)
        self.assertEqual(observed.execute('SELECT 42'),42)
        with self.assertRaises(Cancelled) as caught:observed.execute('FAIL')
        self.assertIs(caught.exception,error)
        self.assertEqual(observed.metrics()[-1]['sqlstate'],'57014')
        self.assertEqual(observed.observer_failures,4)


if __name__=='__main__':unittest.main()
