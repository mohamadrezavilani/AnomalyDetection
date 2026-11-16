"""READ ONLY source probe stays bounded, private and outside publication claims."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_online import publish_capture
from tests import test_viewer_contract_fetch_once as contract_tests
from viewer_performance import Observe_Viewer_Index_Cost as probe
from viewer_performance.capacity.baseline import semantic_snapshot
from viewer_performance.capacity.fixtures import corpus,FIVE


class ProbeContracts(unittest.TestCase):
    def test_unrelated_and_unallocated_database_names_never_connect(self):
        import psycopg
        with patch('psycopg.connect',side_effect=AssertionError('must not connect')):
            for name in ('application','pishkhan24_shadow','p24_design_unallocated'):
                with self.assertRaisesRegex(ValueError,'owned_test_database'):
                    probe.observe({'dbname':name})

    def test_plan_export_omits_conditions_outputs_and_literals(self):
        source=dict(Plan={'Node Type':'Index Scan','Actual Rows':0,'Actual Loops':1,
            'Index Name':'vei_binary_origin_v1','Index Cond':'private-key',
            'Output':['private-value'],'Shared Read Blocks':2},
            **{'Execution Time':1,'Planning Time':2})
        result=probe.plan_summary(source)
        self.assertNotIn('private-',json.dumps(result))
        self.assertEqual(result['shared_read_blocks'],2)


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'isolated PG18 not configured')
class NativeIndexProbe(unittest.TestCase):
    native=True
    setUpClass=classmethod(contract_tests.NativeContractFetchTests.setUpClass.__func__)
    tearDownClass=classmethod(contract_tests.NativeContractFetchTests.tearDownClass.__func__)
    database=contract_tests.ContractChecks.database

    def test_native_probe_is_read_only_keeps_data_and_exports_no_sql_or_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys)
            with self.database(ViewerDB,root,keys) as db:
                job=corpus(root,(1,1,1))[0]
                publish_capture(db,job['path'],job['start'],job['start']+FIVE)
                db.sql('SELECT pg_advisory_lock(240026,1)')
                before=semantic_snapshot(db);db.conn.rollback()
                db.sql("SELECT 'private-probe-sentinel' AS value")
                config={**self.parameters,'dbname':db.conn.info.dbname}
                result=probe.observe(config,seconds=3,pairs=2,batch_size=8,_qualification=True)
                self.assertEqual(result['status'],'READ_ONLY_INDEX_COST_OBSERVATION')
                self.assertEqual(result['completed_pairs'],2)
                settings={row['name']:row['setting'] for row in result['settings']}
                self.assertEqual(settings['default_transaction_read_only'],'on')
                self.assertTrue(result['writer_before'])
                self.assertNotIn('private-probe-sentinel',json.dumps(result))
                self.assertTrue(all(row['returned_rows']==0 for row in result['samples']))
                self.assertTrue(all('Index Cond' not in json.dumps(row) for row in result['samples']))
                self.assertEqual(before,semantic_snapshot(db));db.conn.rollback()
                self.assertFalse(result['database_modified'])
                self.assertFalse(result['physical_disk_reads_inferred'])


if __name__=='__main__':unittest.main()
