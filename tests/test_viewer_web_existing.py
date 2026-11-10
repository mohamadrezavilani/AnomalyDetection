"""Starting only Web must never initialize schema or synchronize catalogs."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock

spec=importlib.util.spec_from_file_location('existing_web',Path(__file__).resolve().parents[1]/'viewer_performance/Run_Viewer_Web.py')
web=importlib.util.module_from_spec(spec);spec.loader.exec_module(web)


class ExistingWebTests(unittest.TestCase):
    def test_postgres_preflight_only_reads_metadata_with_a_bounded_read_only_transaction(self):
        db=Mock();db.sqlite=False;db.all.return_value=[{'relname':name} for name in web.REQUIRED]
        factory=Mock();factory.return_value.__enter__=Mock(return_value=db);factory.return_value.__exit__=Mock(return_value=False)
        web.check_existing({'config':{'dbname':'p24_design_viewer'}},database_factory=factory)
        db.init.assert_not_called();db.init_semantic_index.assert_not_called();db.sync_service_catalog.assert_not_called()
        self.assertEqual(db.sql.call_args_list[0].args[0],'SET TRANSACTION READ ONLY')
        self.assertTrue(db.all.call_args.args[0].startswith('SELECT '))
        self.assertIn('pg_catalog.pg_class',db.all.call_args.args[0])

    def test_missing_schema_is_reported_instead_of_creating_it(self):
        db=Mock();db.sqlite=False;db.all.return_value=[]
        factory=Mock();factory.return_value.__enter__=Mock(return_value=db);factory.return_value.__exit__=Mock(return_value=False)
        with self.assertRaisesRegex(ValueError,'start_existing_viewer_worker_first'):
            web.check_existing({},database_factory=factory)
        db.init.assert_not_called()

    def test_only_the_existing_app_is_started_on_loopback_without_reloader(self):
        factory=Mock();options={'fixture':'existing'}
        web.serve_existing(options,factory=factory)
        factory.assert_called_once_with(options)
        factory.return_value.run.assert_called_once_with(host='127.0.0.1',port=5021,use_reloader=False,debug=False)


if __name__=='__main__':unittest.main()
