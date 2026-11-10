"""Transaction-local input snapshots retain global conflict and orphan semantics."""
from pathlib import Path
import tempfile
import unittest

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB,token
from tests.test_viewer_online import verified_file
from tests.test_viewer_r6_service_journey import log,sql


class ScopedInputTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);generate_keys(self.root/'keys')
        self.db=ViewerDB(sqlite_path=self.root/'db',keys_path=self.root/'keys');self.addCleanup(self.db.close)
        self.db.init()
        rows=[log(1,'a','Services.v1/WaterBills Line:1','POST (G00000 | successful)'),
            log(2,'a','DBPath.x.ud_prc_userSessionHasAccess',sql('ud_prc_userSessionHasAccess',session='b'*32)),
            log(3,'b','Services.v1/GasBills Line:1','POST (G00000 | successful)')]
        self.db.ingest([verified_file(self.root/'first.gz',rows)]);self.db.rebuild()
        self.key=token(self.db.keys,'request','a')
        self.db.rebuild(request_keys=[self.key],commit=False)
        self.db._prepare_projection_inputs()

    def test_cached_access_and_global_versions_match_original_fences(self):
        def execute(cached):
            self.db.sql('SAVEPOINT compare_inputs')
            try:
                self.db.sql("UPDATE viewer_requests SET identity_state='assigned',conflicted=0")
                self.db.sql(self.db._access_session_conflicts_sql('viewer_projection_events',scoped=True,indexed=True,cached=cached))
                return self.db.all('SELECT request_key,identity_state,conflicted FROM viewer_requests ORDER BY request_key')
            finally:self.db.sql('ROLLBACK TO SAVEPOINT compare_inputs');self.db.sql('RELEASE SAVEPOINT compare_inputs')
        self.assertEqual(execute(False),execute(True))

    def test_origin_version_in_another_request_is_included_and_refresh_is_not_persistent(self):
        original=self.db.one('SELECT * FROM viewer_projection_events ORDER BY origin_key LIMIT 1')
        self.assertEqual(self.db.one('SELECT version_count FROM viewer_projection_versions WHERE origin_key=?',
            (original['origin_key'],))['version_count'],1)
        columns=[d[0] for d in self.db.sql('SELECT * FROM viewer_events LIMIT 0').description]
        changed=dict(original,version_key='new-version',request_key=token(self.db.keys,'request','outside'))
        self.db.sql('INSERT INTO viewer_events VALUES('+','.join('?' for _ in columns)+')',[changed[c] for c in columns])
        self.db._prepare_projection_inputs()
        count=self.db.one('SELECT version_count FROM viewer_projection_versions WHERE origin_key=?',(original['origin_key'],))['version_count']
        self.assertEqual(count,2)
        for cached in (False,True):
            expression=self.db._single_version_origin_sql(indexed=True,cached=cached)
            self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_projection_events e WHERE e.origin_key=? AND '+expression,
                (original['origin_key'],))['n'],0)

    def test_link_only_origin_and_missing_version_keep_the_previous_admission_rule(self):
        self.db.sql('INSERT INTO viewer_links VALUES(?,?,?,?,?)',('missing-origin','missing-version',self.key,'invoice','id'))
        self.db._prepare_projection_inputs()
        self.assertEqual(self.db.one("SELECT version_count FROM viewer_projection_versions WHERE origin_key='missing-origin'")['version_count'],0)
        results=[]
        for cached in (False,True):
            table='viewer_projection_links' if cached else 'viewer_links'
            results.append(self.db.all('SELECT origin_key,version_key FROM '+table+' l WHERE request_key=? AND '+
                self.db._single_version_origin_sql('l',indexed=True,cached=cached)+' ORDER BY 1,2',(self.key,)))
        self.assertEqual(*results)

    def test_hot_query_bodies_have_only_scoped_link_and_validity_dependencies(self):
        query=self.db._access_session_conflicts_sql('viewer_projection_events',scoped=True,indexed=True,cached=True)
        self.assertIn('viewer_projection_links',query);self.assertIn('viewer_projection_versions',query)
        self.assertNotIn('FROM viewer_events',query);self.assertNotIn('FROM viewer_links',query)
        native=object.__new__(ViewerDB);native.sqlite=False;native._active_projection_scope=True
        queries=[]
        native.all=lambda q,p=():queries.append(q) or []
        native._reconcile_payment_outcomes()
        self.assertTrue(queries)
        self.assertTrue(all('FROM viewer_events' not in q and 'FROM viewer_links' not in q for q in queries))


if __name__=='__main__':unittest.main()
