"""C1 negative-only membership, source fences and real process recovery.

Only disposable qualification databases are allocated. No product connection,
configuration, Capture, source key or persisted filter is loaded by these tests.
"""
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB,source_identity,token
from p24_foundation.viewer_online import bind_stream,initialize_live,publish_capture
from viewer_performance.capacity.baseline import run,semantic_snapshot
from viewer_performance.capacity.fixtures import corpus,write,row,START,FIVE
from viewer_performance.capacity.origin_filter import Membership,OriginFilteredDB


def interrupted_publication(options,capture,start,point):
    with OriginFilteredDB(**options) as db:
        db.prepare_candidate()
        publish_capture(db,capture,start,start+FIVE,
            fault=lambda stage:os._exit(73) if stage==point else None)
    os._exit(74)


class MembershipTests(unittest.TestCase):
    def test_incomplete_filter_never_returns_a_negative_and_complete_filter_has_no_false_negatives(self):
        membership=Membership(1024)
        values=['origin:'+str(i) for i in range(300)]+['منشأ:الف','full-prefix-1','full-prefix-2']
        self.assertTrue(membership.maybe('not_built'))
        for value in values:membership.add(value)
        membership.ready=True
        self.assertTrue(all(membership.maybe(value) for value in values))
        self.assertTrue(any(not membership.maybe('absent:'+str(i)) for i in range(300)))
        membership.disable('test_fence')
        self.assertTrue(all(membership.maybe('unknown:'+str(i)) for i in range(100)))

    def test_saturation_only_degrades_to_authoritative_lookup(self):
        membership=Membership(32);membership.bits[:]=b'\xff'*32;membership.ready=True
        self.assertTrue(all(membership.maybe(str(i)) for i in range(100)))
        self.assertEqual(membership.negative_checks,0)
        for size in (0,31,1000,128*1024**2):
            with self.assertRaises(ValueError):Membership(size)

    def test_product_database_rejected_before_connection(self):
        with patch.object(ViewerDB,'__init__',side_effect=AssertionError('opened product')):
            with self.assertRaisesRegex(ValueError,'qualification_only'):
                OriginFilteredDB(config={'dbname':'p24_design_viewer'})


class FilterChecks:
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);keys=self.root/'keys';generate_keys(keys)
        if getattr(self,'native',False):
            name='p24_design_capacity_'+uuid.uuid4().hex[:16]+'_qualification'
            self.admin.execute(self.pgsql.SQL('CREATE DATABASE {}').format(self.pgsql.Identifier(name)))
            self.addCleanup(lambda:self.admin.execute(self.pgsql.SQL('DROP DATABASE {}').format(self.pgsql.Identifier(name))))
            self.options=dict(config={**self.parameters,'dbname':name,'options':'-c jit=off'},keys_path=keys)
        else:self.options=dict(sqlite_path=self.root/'viewer.db',keys_path=keys)
        self.db=OriginFilteredDB(**self.options);self.addCleanup(self.db.close)
        self.db.init();initialize_live(self.db);bind_stream(self.db,start_ns=START,stream_key='filter-tests')
        self.jobs=corpus(self.root,(2,3,4))
        self.publish(self.jobs[0]);self.db.conn.rollback();self.db.prepare_candidate()

    def publish(self,job,*,fault=None,acknowledge=True):
        result=publish_capture(self.db,job['path'],job['start'],job['start']+FIVE,
            mode=job['mode'],fault=fault)
        if acknowledge:self.db.candidate_after_publication(result)
        return result

    def test_every_boundary_equal_with_cross_request_conflicts_and_late_payment(self):
        report=run(backend='postgresql' if getattr(self,'native',False) else 'sqlite',
            counts=(2,3,4),pairs=2,experiment='origin_filter')
        self.assertEqual(report['status'],'PASS_CANDIDATE_EQUIVALENCE',report.get('failure'))
        self.assertEqual(report['checks'][1]['order'],['origin_filter','baseline'])
        for lane in report['lanes']:
            if lane['variant']!='origin_filter':continue
            candidate=lane['candidate_report']
            self.assertTrue(candidate['membership']['ready'])
            self.assertGreater(candidate['lookup']['skipped_negatives'],0)
            self.assertGreater(candidate['lookup']['authoritative_origins'],0)
            self.assertEqual(candidate['lookup']['fallback_publications'],1)  # seed only
            self.assertGreater(lane['windows'][-1]['semantic_states'].get('withdrawn',0),0)

    def test_ordinary_new_evidence_rebuilds_existing_request_and_keeps_full_identity(self):
        old=self.db.lookup_request('late');self.db.conn.rollback()
        result=self.publish(self.jobs[1])
        current=self.db.lookup_request('late')
        self.assertGreater(result['new_events'],0)
        self.assertEqual(current['request_key'],old['request_key'])
        self.assertGreater(current['event_count'],old['event_count'])
        self.assertTrue(self.db.membership.ready)
        self.assertGreater(self.db.lookup_stats['skipped_negatives'],0)

    def test_all_bits_positive_uses_the_unchanged_full_lookup(self):
        self.db.membership.bits[:]=b'\xff'*len(self.db.membership.bits)
        result=self.publish(self.jobs[1])
        self.assertGreater(result['new_events'],0)
        self.assertEqual(self.db.lookup_stats['skipped_negatives'],0)
        self.assertGreater(self.db.lookup_stats['authoritative_origins'],0)
        self.assertTrue(self.db.membership.ready)

    def test_incomplete_build_rollback_never_enables_negatives(self):
        before=semantic_snapshot(self.db);self.db.conn.rollback()
        def fail(count):raise RuntimeError('build_interrupted')
        with self.assertRaisesRegex(RuntimeError,'build_interrupted'):
            self.db.prepare_candidate(fault=fail)
        self.assertFalse(self.db.membership.ready)
        self.assertTrue(self.db.membership.maybe('not_in_partial_build'))
        self.assertEqual(before,semantic_snapshot(self.db));self.db.conn.rollback()
        self.publish(self.jobs[1])
        self.assertEqual(self.db.lookup_stats['skipped_negatives'],0)

    def test_rolled_back_new_bits_are_safe_false_positives_on_retry(self):
        before=semantic_snapshot(self.db);self.db.conn.rollback()
        def fail(stage):
            if stage=='before_commit':raise RuntimeError('rollback_publication')
        with self.assertRaisesRegex(RuntimeError,'rollback_publication'):
            self.publish(self.jobs[1],fault=fail)
        self.assertEqual(before,semantic_snapshot(self.db));self.db.conn.rollback()
        self.assertTrue(self.db.membership.ready)
        skipped=self.db.lookup_stats['skipped_negatives']
        result=self.publish(self.jobs[1])
        self.assertGreater(result['new_events'],0)
        self.assertEqual(self.db.lookup_stats['skipped_negatives'],skipped)
        self.assertGreater(self.db.lookup_stats['authoritative_origins'],0)
        self.assertTrue(self.db.membership.ready)

    def test_supported_maintenance_invalidates_the_filter_before_a_new_publication(self):
        self.db.write_lock();self.db.conn.commit()
        self.publish(self.jobs[1])
        self.assertFalse(self.db.membership.ready)
        self.assertEqual(self.db.membership.disabled_reason,'source_fence_changed')
        self.assertEqual(self.db.lookup_stats['skipped_negatives'],0)

    def test_unacknowledged_commit_and_runtime_change_fall_back(self):
        self.publish(self.jobs[1],acknowledge=False)
        previous=self.db.lookup_stats['skipped_negatives']
        self.publish(self.jobs[2])
        self.assertEqual(self.db.lookup_stats['skipped_negatives'],previous)
        self.assertFalse(self.db.membership.ready)
        self.db.conn.rollback();self.db.prepare_candidate()
        with patch('viewer_performance.capacity.origin_filter.runtime_source_digest',return_value='other'):
            self.publish(self.jobs[3])
        self.assertFalse(self.db.membership.ready)
        self.assertEqual(self.db.membership.disabled_reason,'runtime_pin_changed')

    def test_changed_contract_is_uncertain_and_legacy_lookup_is_not_credited(self):
        # An unknown membership contract disables negatives. The unchanged
        # authoritative lookup remains available to the original publisher.
        self.db.sql("UPDATE viewer_window_epoch_state SET contract='unknown' WHERE id=1");self.db.conn.commit()
        self.publish(self.jobs[1])
        self.assertFalse(self.db.membership.ready)
        self.assertEqual(self.db.lookup_stats['skipped_negatives'],0)
        self.db.conn.rollback()
        self.db.sql("UPDATE viewer_window_epoch_state SET contract='viewer-window-epochs-1' WHERE id=1");self.db.conn.commit()
        self.db.prepare_candidate();self.db._qualification_origin_lookup='legacy'
        self.publish(self.jobs[2])
        self.assertFalse(self.db.membership.ready)
        self.assertEqual(self.db.membership.disabled_reason,'lookup_strategy_changed')
        self.assertEqual(self.db.lookup_stats['skipped_negatives'],0)

    def test_real_process_death_before_and_after_commit_restarts_from_durable_state(self):
        ctx=multiprocessing.get_context('spawn')
        for point,job,committed in (('before_commit',self.jobs[1],False),('after_commit',self.jobs[2],True)):
            before=semantic_snapshot(self.db);self.db.conn.rollback()
            child=ctx.Process(target=interrupted_publication,args=(self.options,job['path'],job['start'],point))
            child.start();child.join(30)
            if child.is_alive():child.kill();child.join();self.fail('crash child timed out')
            self.assertEqual(child.exitcode,73)
            after=semantic_snapshot(self.db);self.db.conn.rollback()
            self.assertEqual(before==after,not committed)
            # A new connection always starts without a filter; build from the
            # committed source, then reconcile retry without missing versions.
            self.db.close();self.db=OriginFilteredDB(**self.options);self.addCleanup(self.db.close)
            self.assertIsNone(self.db.membership);self.db.prepare_candidate()
            retry=dict(job)
            if committed:retry['mode']='recheck'
            result=self.publish(retry)
            self.assertEqual(result['new_events']==0,committed)
            self.assertTrue(self.db.membership.ready)


class SQLiteFilterTests(FilterChecks,unittest.TestCase):pass


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'isolated PG18 not configured')
class NativeFilterTests(FilterChecks,unittest.TestCase):
    native=True

    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        cls.pgsql=sql
        cls.parameters=dict(host=os.environ['P24_DELTA_PG_HOST'],
            port=int(os.environ.get('P24_DELTA_PG_PORT','5432')),
            user=os.environ.get('P24_DELTA_PG_USER','postgres'),connect_timeout=3)
        cls.admin=psycopg.connect(**cls.parameters,dbname='postgres',autocommit=True)

    @classmethod
    def tearDownClass(cls):cls.admin.close()


if __name__=='__main__':unittest.main()
