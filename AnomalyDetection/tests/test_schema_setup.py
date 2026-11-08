import unittest
from anomaly_detection.schema_setup import declaration,columns
from anomaly_detection.snapshot import ContractError


class SchemaSetupTests(unittest.TestCase):
    def test_rejects_public_or_unrecognized_mutations_before_database_access(self):
        for query in ('CREATE TABLE IF NOT EXISTS public.viewer_bad(x TEXT)',
                      'DROP TABLE anomaly_detection.adp_state',
                      'ALTER TABLE anomaly_detection.adp_jobs DROP COLUMN body'):
            with self.subTest(query=query),self.assertRaises(ContractError):declaration(query)

    def test_composite_key_is_not_a_column_and_types_and_literal_default_survive(self):
        result=columns("actor TEXT NOT NULL,target BIGINT,score DOUBLE PRECISION,scope TEXT DEFAULT 'BEHAVIOR_TARGET',PRIMARY KEY(actor,target)")
        self.assertEqual(set(result),{'actor','target','score','scope'})
        self.assertEqual(result['score']['type'],'double precision')
        self.assertEqual(result['scope']['default'],"'BEHAVIOR_TARGET'")

    def test_every_installed_product_statement_uses_the_restricted_owned_grammar(self):
        from importlib import import_module
        modules=('product_store','product_dependencies','product_pipeline','product_enrichment','service_reference','product_priority','job_scope','cases','population','model_queue','scenario_store')
        statements=[q for name in modules for q in import_module('anomaly_detection.'+name).DDL]
        self.assertEqual(len(statements),111)
        self.assertEqual({declaration(q)[0] for q in statements},{'table','index','column','default'})


if __name__=='__main__':unittest.main()
