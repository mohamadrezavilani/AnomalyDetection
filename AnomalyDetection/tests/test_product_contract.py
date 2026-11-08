"""Semantic identity/unknown evidence and bounded source access invariants."""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from anomaly_detection.product_store import core
from anomaly_detection.product_source import ProductSource
from anomaly_detection.snapshot import Snapshot,ContractError,digest
from anomaly_detection.pg_source import BudgetQuery,read_database_config
from tests.fixture_factory import initial,key


class ProductContractTests(unittest.TestCase):
    def row(self):
        fixture=initial();semantic=deepcopy(fixture['tables']['viewer_semantic_occurrences'][0])
        request=next(row for row in fixture['tables']['viewer_requests'] if row['request_key']==semantic['request_key'])
        return semantic|{'identity_state':request['identity_state'],'conflicted':request['conflicted'],'request_session_key':request['session_key']}
    def test_boolean_representation_does_not_create_false_revisions(self):
        row=self.row();self.assertEqual(digest(core(row)),digest(core(row|{'conflicted':False})))
    def test_request_session_conflict_cannot_train_activity_models(self):
        self.assertFalse(core(self.row()|{'request_session_key':'f'*64})['eligible'])
        self.assertFalse(core(self.row()|{'conflicted':1})['eligible'])
    def test_technical_invoice_and_reservation_are_not_service_executions(self):
        self.assertFalse(core(self.row()|{'root_call':'Services.v1/InvoiceRegister'})['eligible'])
        self.assertFalse(core(self.row()|{'kind':'product_reservation'})['eligible'])
    def test_null_root_in_reservation_remains_a_retained_valid_fact(self):
        value=core(self.row()|{'kind':'product_reservation','root_call':None})
        self.assertFalse(value['eligible']);self.assertFalse(value['service_path'])
        self.assertEqual(value['anchor_key'],self.row()['anchor_key'])
    def test_missing_business_evidence_is_not_financial_success(self):
        snapshot=initial();snapshot['tables']['viewer_contract_observations']=[]
        self.assertTrue(all(not fact['outcomes'] for fact in Snapshot(snapshot).facts()))
    def test_explicit_audit_scope_is_canonical_even_when_queue_due_order_differs(self):
        reader=ProductSource.__new__(ProductSource)
        @contextmanager
        def snapshot():yield object()
        reader.snapshot=snapshot
        from types import SimpleNamespace
        sample=SimpleNamespace(occurrences={})
        with patch('anomaly_detection.product_source.collect_sample',return_value=(sample,{})) as collect:
            self.assertIs(reader.audit([key(8),key(1),key(2)]),sample)
            self.assertEqual(collect.call_args.kwargs['request_keys'],[key(1),key(2),key(8)])
    def test_database_configuration_is_data_not_executed_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            config=Path(temporary)/'viewer_config.local.py';sentinel=Path(temporary)/'should-not-exist'
            config.write_text("open("+repr(str(sentinel))+",'w').write('bad')\nDATABASE={'dbname':'p24_design_viewer'}")
            self.assertEqual(read_database_config(config),{'dbname':'p24_design_viewer'});self.assertFalse(sentinel.exists())
    def test_source_budget_rejects_mutation_before_connecting(self):
        with self.assertRaises(ContractError):BudgetQuery(object())('DELETE FROM public.viewer_requests')
    def test_semantic_timeout_cannot_shrink_window_pages(self):
        reader=ProductSource.__new__(ProductSource);reader.page_size=2048;reader.semantic_page_size=2048
        for _ in range(10):reader.reduce_page_size('semantic_keyset')
        self.assertEqual(reader.page_sizes(),{'window':2048,'semantic_keyset':64})
        reader.reduce_page_size('learning_cursor')
        self.assertEqual(reader.page_sizes(),{'window':1024,'semantic_keyset':64})
    def test_failed_read_keeps_safe_timing_without_sql_or_parameters(self):
        class Cancelled(Exception):sqlstate='57014'
        class Cursor:
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def execute(self,sql,args):
                if 'set_config' not in sql:raise Cancelled()
        class Connection:
            def cursor(self):return Cursor()
        query=BudgetQuery(Connection())
        with self.assertRaises(Cancelled):query('SELECT %s',('private-value',))
        self.assertEqual(query.metrics[-1]['sqlstate'],'57014')
        self.assertTrue(query.metrics[-1]['failed'])
        self.assertNotIn('private-value',str(query.metrics));self.assertNotIn('SELECT',str(query.metrics))


if __name__=='__main__':unittest.main()
