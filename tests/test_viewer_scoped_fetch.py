"""Sparse scoped reads retain exact evidence while bounding raw-body fetches."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB,token
from p24_foundation.viewer_contract import CONTRACT_PATTERNS
from tests.test_viewer_online import verified_file
from tests.test_viewer_r6_service_journey import log,sql


class ScopedContractFetchTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);generate_keys(self.root/'keys')
        self.db=ViewerDB(sqlite_path=self.root/'viewer',keys_path=self.root/'keys')
        self.addCleanup(self.db.close);self.db.init()
        self.rows=[]
        for n in range(720):
            request='target_'+str(n) if n<620 else 'unrelated_'+str(n)
            self.rows.extend([log(2*n,request,'Services.v1/WaterBills Line:1','POST (G00000 | successful)'),
                log(2*n+1,request,'DBPath.x.ud_prc_invoiceRegister',sql('ud_prc_invoiceRegister',invoiceUniqueID='invoice_'+str(n)))])
        self.db.ingest([verified_file(self.root/'source.gz',self.rows)])
        self.db.rebuild();self.db.rebuild_payment_contract()
        self.keys=[token(self.db.keys,'request','target_'+str(n)) for n in range(620)]
        self.db.rebuild(request_keys=self.keys)

    def expected(self):
        return self.db.all(self.db._contract_read_query(scoped=True),CONTRACT_PATTERNS)

    def test_sparse_reader_matches_original_join_and_bounds_body_lookups(self):
        expected=self.expected();queries=[];original=self.db.sql;timings={}
        def trace(statement,params=()):queries.append((statement,len(params)));return original(statement,params)
        with patch.object(self.db,'sql',side_effect=trace):
            with self.db.contract_event_batches(scoped=True,timings=timings) as batches:
                actual=[row for batch in batches for row in batch]
        self.assertEqual(actual,expected)
        self.assertEqual(timings['candidate_events'],620)
        raw_queries=[size for statement,size in queries if statement.startswith('SELECT origin_key,version_key,payload FROM viewer_raw_events WHERE')]
        self.assertEqual(raw_queries,[800,440])
        self.assertTrue(any(statement.startswith('SELECT * FROM viewer_contract_candidate_scope') for statement,_ in queries))
        self.assertFalse(any('b.payload FROM viewer_events' in statement for statement,_ in queries))

    def test_scoped_rebuild_preserves_unrelated_relations_and_full_batch_parity(self):
        tables=('viewer_contract_identifiers','viewer_contract_edges','viewer_contract_observations')
        before={table:self.db.all('SELECT * FROM '+table+' ORDER BY 1,2') for table in tables}
        self.db.rebuild_payment_contract(request_keys=self.keys)
        self.assertEqual(before,{table:self.db.all('SELECT * FROM '+table+' ORDER BY 1,2') for table in tables})

    def test_missing_raw_and_material_conflict_have_same_exclusion_as_old_reader(self):
        changed=dict(self.rows[1],RequestID='moved',message='changed material')
        self.db.ingest([verified_file(self.root/'revision.gz',[changed])])
        origin,version=self.db.raw_keys(self.rows[3],'unused',3)
        self.db.sql('DELETE FROM viewer_raw_events WHERE origin_key=? AND version_key=?',(origin,version))
        expected=self.expected()
        with self.db.contract_event_batches(scoped=True) as batches:actual=[row for batch in batches for row in batch]
        self.assertEqual(actual,expected)
        self.assertEqual(len(actual),618)

    def test_max_events_keeps_original_order_and_scope(self):
        expected=self.expected()[:17]
        unrelated=self.db.all('SELECT * FROM viewer_contract_identifiers WHERE request_key NOT IN (SELECT request_key FROM viewer_projection_scope) ORDER BY 1,2')
        info=self.db.rebuild_payment_contract(request_keys=self.keys,max_events=17)
        self.assertEqual(info['scanned_events'],17)
        selected=self.db.all('SELECT origin_key,version_key FROM viewer_contract_identifiers WHERE request_key IN (SELECT request_key FROM viewer_projection_scope) ORDER BY 1,2')
        self.assertEqual(selected,[dict(origin_key=row['origin_key'],version_key=row['version_key']) for row in expected])
        self.assertEqual(unrelated,self.db.all('SELECT * FROM viewer_contract_identifiers WHERE request_key NOT IN (SELECT request_key FROM viewer_projection_scope) ORDER BY 1,2'))


if __name__=='__main__':unittest.main()
