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


if __name__=='__main__':unittest.main()
