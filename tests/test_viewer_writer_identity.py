"""Lease-bound durable identity, real publication telemetry and observation fences."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_online import single_worker
from viewer_performance.fast_writer import FastWriterDB,activate
from viewer_performance.writer_identity import (WriterIdentity,read_identity,recent_publications,
    LEASE_SQL,ACTIVE,identity_key)
from viewer_performance.Observe_Viewer_Fast import Measurement,ad_prefix_distance,collect
from viewer_performance.capacity.fixtures import corpus,START,FIVE
from viewer_performance.capacity.baseline import run_lane
from tests import test_viewer_contract_fetch_once as fixture


def identity():
    return dict(instance_token='a'*32,python_pid=41,implementation_build='test',
        implementation_source_sha256='b'*64,canonical_runtime_source_sha256='c'*64,
        backend_pid=57,backend_start='start',server_started='server',database_oid=90,
        client_port=999,client_addr='127.0.0.1',application_name='P24.Fast.'+'a'*32,telemetry_slot=0)


class IdentityTests(unittest.TestCase):
    def test_a_commit_before_baseline_logged_late_does_not_count_as_fresh(self):
        owner=identity();test=Measurement(owner,0,0,baseline_generation=12)
        test.add(owner,[dict(sequence=1,generation=12,status='PUBLISHED',new_complete_window=True)])
        self.assertEqual(test.rows,[])
        self.assertEqual(test.sequence,1)
    def test_empty_fresh_coverage_counts_but_rechecking_an_existing_window_does_not(self):
        owner=identity();test=Measurement(owner,0,0)
        rows=[dict(sequence=n,status='PUBLISHED',new_complete_window=new,mode='manual_recheck',
            new_events=0 if new else 5,receive_through_commit_seconds=2,capture_seconds=1,
            commit_seconds=.1,writes={}) for n,new in ((1,True),(2,False),(3,True))]
        test.add(owner,rows,observed=10)
        result=test.summary(20)
        self.assertEqual(result['newly_complete_windows'],2)
        self.assertEqual(result['publications_with_new_evidence'],1)

    def test_ad_prefix_distance_uses_live_lane_cursor_and_reports_unknown_as_unknown(self):
        source=dict(status='READ',next_ns=10*FIVE)
        self.assertIsNone(ad_prefix_distance(source,{}))
        self.assertEqual(ad_prefix_distance(source,dict(window_lanes={'fresh_cursor':{'cursor':{'next_ns':7*FIVE}}})),3)
        self.assertIsNone(ad_prefix_distance(source,dict(fresh_and_verified=False,
            window_lanes={'fresh_cursor':{'cursor':{'next_ns':7*FIVE}}})))

    def test_a_stale_pointer_does_not_establish_a_running_implementation(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);directory=root/'AnomalyDetection/reports';directory.mkdir(parents=True)
            value=identity();(directory/ACTIVE).write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError,'current_lease'):read_identity(root,[])
            lease={k:value[k] for k in ('backend_pid','backend_start','server_started','database_oid','client_port','client_addr','application_name')}
            self.assertEqual(read_identity(root,[lease]),value)
            for key in lease:
                changed=dict(lease);changed[key]='replacement'
                with self.subTest(key=key),self.assertRaises(ValueError):read_identity(root,[changed])

    def test_identity_changes_and_missing_publications_invalidate_measurement(self):
        original=identity()
        for key in original:
            test=Measurement(original,0,0);changed=dict(original);changed[key]='changed'
            test.add(changed,[])
            self.assertEqual(test.failure,'WRITER_IMPLEMENTATION_OR_PROCESS_CHANGED')
        test=Measurement(original,0,0);test.add(original,[dict(sequence=2,status='PUBLISHED')])
        self.assertEqual(test.failure,'WRITER_JOURNAL_GAP')

    def test_first_completion_is_not_a_complete_timed_cycle_and_failures_do_not_count(self):
        original=identity();test=Measurement(original,5,0)
        rows=[dict(sequence=i,status='PUBLISHED',new_events=20,new_complete_window=True,mode='manual_recheck',
            receive_through_commit_seconds=30,capture_seconds=2,commit_seconds=1,
            writes={'viewer_raw_events':dict(seconds=15,calls=1)}) for i in (6,7,8)]
        test.add(original,rows);s=test.summary(90)
        self.assertEqual(s['new_evidence_windows'],3)
        self.assertEqual(s['complete_timed_cycles'],2)
        self.assertEqual(s['receive_through_commit_seconds'],60)
        self.assertEqual(s['ideal_speedup_if_only_measured_final_writes_became_free'],2)
        test.add(original,[dict(sequence=9,status='PUBLICATION_FAILED_OUTCOME_REQUIRES_DATABASE_RECEIPT')])
        self.assertEqual(test.summary(100)['status'],'INVALID')

    def test_bounded_journal_rejects_mixed_identity_and_incomplete_last_line_is_not_a_commit(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);owner=WriterIdentity(root,build='test',source='b'*64,runtime='c'*64)
            owner.directory.mkdir(parents=True);owner.record=identity();owner.token=owner.record['instance_token'];owner.bound=True
            owner.append(dict(status='PUBLISHED'))
            path=owner.directory/'Viewer_Writer_Journal_0_0.jsonl'
            with path.open('ab') as stream:stream.write(b'{"not-complete":')
            self.assertEqual(len(recent_publications(root,owner.record)),1)
            path.write_text(json.dumps(dict(sequence=2,status='PUBLISHED',writer_identity={}))+'\n')
            with self.assertRaisesRegex(ValueError,'journal_identity'):recent_publications(root,owner.record)


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PG18 not configured')
class NativeIdentityTests(unittest.TestCase):
    native=True
    setUpClass=classmethod(fixture.NativeContractFetchTests.setUpClass.__func__)
    tearDownClass=classmethod(fixture.NativeContractFetchTests.tearDownClass.__func__)
    database=fixture.ContractChecks.database

    def test_real_readonly_observer_matches_a_new_commit_to_its_current_lease(self):
        import psycopg
        from psycopg.rows import dict_row
        from p24_foundation.viewer_online import initialize_live,bind_stream
        from AnomalyDetection.validation.observe_viewer_live import Reader,source_inventory
        from viewer_performance.fast_writer import ROOT,verify_sources
        # Allocate this exact reserved name only when it does not exist on the
        # explicitly configured test cluster. Never read/drop an existing DB.
        name='p24_design_viewer'
        self.admin.execute(self.pgsql.SQL('CREATE DATABASE {}').format(self.pgsql.Identifier(name)))
        try:
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1))
                digest=verify_sources();inventory=source_inventory(ROOT);tick=[0.]
                with patch('viewer_performance.fast_writer.ROOT',root),FastWriterDB(
                        config={**self.parameters,'dbname':name},keys_path=keys) as db,activate(),single_worker(db,root/'lock'):
                    db.init();initialize_live(db);bind_stream(db,start_ns=START,stream_key='observer-fixture')
                    from p24_foundation import viewer_online
                    viewer_online.publish_capture(db,jobs[0]['path'],START,START+FIVE)
                    def wait(seconds):
                        tick[0]+=seconds
                        viewer_online.publish_capture(db,jobs[1]['path'],START+FIVE,START+2*FIVE)
                    ad=lambda project:dict(identity=dict(pid=10,instance_token='fixture'),counters={},window_lanes={},
                        input_contract=dict(input_contract='viewer-full-relations-1',scope_epoch=0))
                    with psycopg.connect(**self.parameters,dbname=name,autocommit=True,row_factory=dict_row,
                            options='-c default_transaction_read_only=on') as connection,patch(
                            'viewer_performance.fast_writer.verify_sources',return_value=digest),patch(
                            'AnomalyDetection.validation.observe_viewer_live.source_inventory',return_value=inventory):
                        result=collect(root,Reader(connection),seconds=10,target=1,clock=lambda:tick[0],wait=wait,ad=ad)
                    self.assertEqual(result['status'],'VERIFIED_WRITER_OBSERVATION',result['throughput'])
                    self.assertEqual(result['throughput']['newly_complete_windows'],1)
                    self.assertFalse(result['full_table_oracles_executed'])
                    # A stale AD heartbeat is a failed AD observation, not a
                    # failed publication and not a reason to lose Viewer data.
                    def wait_stale(seconds):
                        tick[0]+=seconds
                        viewer_online.publish_capture(db,jobs[2]['path'],START+2*FIVE,START+3*FIVE)
                    with psycopg.connect(**self.parameters,dbname=name,autocommit=True,row_factory=dict_row,
                            options='-c default_transaction_read_only=on') as connection,patch(
                            'viewer_performance.fast_writer.verify_sources',return_value=digest),patch(
                            'AnomalyDetection.validation.observe_viewer_live.source_inventory',return_value=inventory):
                        degraded=collect(root,Reader(connection),seconds=10,target=1,clock=lambda:tick[0],wait=wait_stale,
                            ad=lambda project:dict(identity=dict(pid=10,instance_token='fixture'),counters={},
                                window_lanes={},fresh_and_verified=False,state='RUNNING_HEARTBEAT_STALE'))
                    self.assertEqual(degraded['status'],'PARTIAL_VERIFIED_WRITER_OBSERVATION')
                    self.assertIsNone(degraded['throughput']['failure'])
                    self.assertEqual(degraded['throughput']['newly_complete_windows'],1)
                    self.assertEqual(len(degraded['publication_receipts']),1)
                    self.assertEqual(degraded['ad_observation_status'],'DEGRADED_OR_UNVERIFIABLE')
                    self.assertEqual(degraded['ad_progress_delta'],{})
        finally:self.admin.execute(self.pgsql.SQL('DROP DATABASE {}').format(self.pgsql.Identifier(name)))

    def test_actual_lease_binding_and_after_commit_receipts_include_index_and_commit_costs(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1))
            with self.database(FastWriterDB,root,keys) as db:
                db.writer_identity.directory=root/'AnomalyDetection/reports'
                db.writer_identity.enabled=True
                self.assertFalse((db.writer_identity.directory/ACTIVE).exists())
                with activate(),single_worker(db,root/'worker.lock'):
                    db.conn.commit()
                    receipt=read_identity(root,db.all(LEASE_SQL))
                    self.assertEqual(receipt['python_pid'],os.getpid())
                    self.assertEqual(receipt['backend_pid'],db.conn.info.backend_pid)
                    from p24_foundation import viewer_online
                    job=jobs[0]
                    result=viewer_online.publish_capture(db,job['path'],START,START+FIVE,capture_seconds=2)
                    rows=recent_publications(root,receipt)
                    self.assertEqual(len(rows),1)
                    saved=db.one('SELECT generation,new_events FROM viewer_live_receipts WHERE start_ns=?',(START,))
                    self.assertEqual(rows[0]['generation'],saved['generation'])
                    self.assertEqual(rows[0]['new_events'],saved['new_events'])
                    self.assertGreater(rows[0]['commit_seconds'],0)
                    self.assertGreater(rows[0]['writes']['viewer_events']['seconds'],0)
                    self.assertGreaterEqual(rows[0]['receive_through_commit_seconds'],2)
                with self.assertRaisesRegex(ValueError,'current_lease'):read_identity(root,db.all(LEASE_SQL))

    def test_capacity_lane_does_not_execute_the_full_evidence_oracle(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1))
            with self.database(ViewerDB,root,keys) as db:
                db.sql('UPDATE viewer_live_state SET stream_key=? WHERE id=1',('capacity-fixed-corpus',));db.conn.commit()
                options=dict(config={**self.parameters,'dbname':db.conn.info.dbname},keys_path=keys)
                with patch('viewer_performance.capacity.baseline.semantic_snapshot',side_effect=AssertionError('full oracle polluted capacity')):
                    lane=run_lane(options,jobs,profiled=False,db_type=FastWriterDB,oracle=False)
                self.assertTrue(all(w['oracle'] is None and not w['full_oracle_executed'] for w in lane['windows']))


if __name__=='__main__':unittest.main()
