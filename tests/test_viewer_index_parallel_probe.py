"""Actual-index reader calibration requires two live identities, changes none."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_online import publish_capture
from tests import test_viewer_contract_fetch_once as fixtures
from viewer_performance.capacity.baseline import semantic_snapshot
from viewer_performance.capacity.fixtures import corpus,START,FIVE
from viewer_performance import Observe_Viewer_Index_Parallel as probe


class ParallelProbeContracts(unittest.TestCase):
    def test_unapproved_database_or_absent_ad_never_opens_a_source_connection(self):
        import psycopg
        with patch('psycopg.connect',side_effect=AssertionError('must not connect')):
            with self.assertRaises(ValueError):probe.observe({'dbname':'p24_design_unallocated'},lambda:{'instance_token':'fixture'})
            with self.assertRaisesRegex(ValueError,'ad_process_identity_required'):
                probe.observe({'dbname':'p24_design_viewer'},lambda:{})

    def test_real_script_entrypoint_works_outside_project_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            env={k:v for k,v in os.environ.items() if k!='PYTHONPATH'}
            result=subprocess.run([sys.executable,'-B',str(Path(probe.__file__)),'--help'],cwd=folder,
                env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_ad_observer_requires_current_identity_and_fresh_heartbeat(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'AnomalyDetection').mkdir()
            (root/'AnomalyDetection/RELEASE_MANIFEST.json').write_text(json.dumps({'build_id':'fixture','source_sha256':'source'}))
            good=dict(running=True,observation_matches_process=True,heartbeat_age_seconds=1.,health='RUNNING',
                process={'owner':dict(instance_token='token',pid=1,build_id='fixture',source_sha256='source')},worker={})
            for change in ({},{'running':False},{'heartbeat_age_seconds':31},{'observation_matches_process':False}):
                value={**good,**change};result=subprocess.CompletedProcess([],0,json.dumps(value))
                with patch.object(probe.subprocess,'run',return_value=result):
                    if change:
                        with self.assertRaisesRegex(ValueError,'fresh_heartbeat_required'):probe.ad_status(root)
                    else:self.assertEqual(probe.ad_status(root)['instance_token'],'token')


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'isolated PG18 not configured')
class NativeParallelProbe(unittest.TestCase):
    native=True
    setUpClass=classmethod(fixtures.NativeContractFetchTests.setUpClass.__func__)
    tearDownClass=classmethod(fixtures.NativeContractFetchTests.tearDownClass.__func__)
    database=fixtures.ContractChecks.database

    def observe(self,db,**kwargs):
        config={**self.parameters,'dbname':db.conn.info.dbname}
        return probe.observe(config,lambda:dict(instance_token='qualification-ad-fixture'),seconds=10,
            _qualification=True,**kwargs)

    def test_native_probe_preserves_every_boundary_and_exports_no_keys_or_sql(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys)
            with self.database(ViewerDB,root,keys) as db:
                job=corpus(root,(1,1,1))[0];publish_capture(db,job['path'],START,START+FIVE)
                db.sql('SELECT pg_advisory_lock(240026,1)')
                before=semantic_snapshot(db);db.conn.rollback()
                original=probe.secrets.token_hex;generated=[]
                def synthetic_key(n):
                    value=original(n);generated.append(value);return value
                with patch.object(probe.secrets,'token_hex',side_effect=synthetic_key):result=self.observe(db)
                self.assertEqual(result['status'],'READ_ONLY_PARALLEL_INDEX_OBSERVATION')
                self.assertTrue(result['workers_observed_alive_and_unchanged'])
                self.assertEqual(result['complete_cells'],12)
                self.assertEqual([c['workers'] for c in result['cells'][:6]],[1,2,4,4,2,1])
                self.assertEqual(before,semantic_snapshot(db));db.conn.rollback()
                exported=json.dumps(result)
                for value in generated:self.assertNotIn(value,exported)
                for forbidden in ('Index Cond','private-probe-sentinel','secret_password','actual_user_key_value'):
                    self.assertNotIn(forbidden,exported)
                self.assertFalse(result['database_modified']);self.assertFalse(result['workers_restarted'])
                self.assertTrue(result['qualification_ad_fixture'])

    def test_changed_ad_identity_is_never_reported_as_verified_concurrency(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys)
            with self.database(ViewerDB,root,keys) as db:
                db.sql('SELECT pg_advisory_lock(240026,1)');db.conn.commit()
                identities=iter((dict(instance_token='before'),dict(instance_token='after')))
                result=probe.observe({**self.parameters,'dbname':db.conn.info.dbname},lambda:next(identities),
                    seconds=10,_qualification=True)
                self.assertEqual(result['status'],'PARTIAL_READ_ONLY_PARALLEL_INDEX_OBSERVATION')
                self.assertFalse(result['workers_observed_alive_and_unchanged'])


if __name__=='__main__':unittest.main()
