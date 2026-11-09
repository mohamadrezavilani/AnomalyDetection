"""Populated predecessor-schema migration and receipt-ledger acceptance."""
import copy
import hashlib
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import psycopg

from p24_foundation.config import connect
from p24_foundation.errors import FoundationError
from p24_foundation.privacy import canonical
from p24_foundation import store as store_module
from p24_foundation.store import FoundationStore, initialize, _backfill_source_manifest_receipts, jsonb
from tests.helpers import TEST_KEYS, batch, document, issue_test_access_token, test_access_policy
from tests.source_backfill_helpers import SchemaConnection, legacy_source, pre_2h_schema


class SourceBackfillContractTests(unittest.TestCase):
    def test_invalid_batch_sizes_are_rejected_before_database_access(self):
        for value in (0,251,True,"2",None):
            with self.subTest(value=value),self.assertRaises(FoundationError) as caught:
                _backfill_source_manifest_receipts(SimpleNamespace(autocommit=True),batch_size=value)
            self.assertEqual(caught.exception.code,"invalid_backfill_batch_size")

    def test_invalid_batch_budgets_are_rejected_before_database_access(self):
        for value in (0,1001,True,"2"):
            with self.subTest(value=value),self.assertRaises(FoundationError) as caught:
                _backfill_source_manifest_receipts(SimpleNamespace(autocommit=True),max_batches=value)
            self.assertEqual(caught.exception.code,"invalid_backfill_batch_budget")

    def test_backfill_refuses_an_outer_transaction_that_cannot_commit_its_batches(self):
        with self.assertRaises(FoundationError) as caught:
            _backfill_source_manifest_receipts(SimpleNamespace(autocommit=False))
        self.assertEqual(caught.exception.code,"backfill_requires_autocommit")


class SourceBackfillPostgresTests(unittest.TestCase):
    database_config=None

    @classmethod
    def setUpClass(cls):
        if cls.database_config is None:
            raise unittest.SkipTest("disposable PostgreSQL configuration required")

    def setUp(self):
        self.schema="p24_backfill_"+uuid.uuid4().hex
        self.tmp=tempfile.TemporaryDirectory()
        self.namespace="legacy_"+uuid.uuid4().hex
        self.token=issue_test_access_token(self.namespace)
        self.native=connect(self.database_config)
        self.c=SchemaConnection(self.native,self.schema)
        self.addCleanup(self.cleanup)
        pre_2h_schema(self.c)
        self.bind_store()
        self.assertIsNone(self.c.execute("SELECT to_regclass('"+self.schema+".foundation_source_manifest')").fetchone()[0])
        self.assertEqual(self.c.execute("SELECT count(*) FROM p24_next.design_version").fetchone(),(8,))

    def bind_store(self):
        self.store=FoundationStore(self.c,TEST_KEYS,self.namespace,Path(self.tmp.name)/"vault",
                                   access_policy=test_access_policy(self.namespace))

    def cleanup(self):
        if self.native.closed:
            self.native=connect(self.database_config)
        self.native.rollback()
        self.native.autocommit=True
        # Only this test's random schema is ever removed, never p24_next.
        self.native.execute('DROP SCHEMA IF EXISTS '+self.schema+' CASCADE')
        self.native.close()
        self.tmp.cleanup()

    def restart(self):
        self.native.close()
        self.native=connect(self.database_config)
        self.c=SchemaConnection(self.native,self.schema)
        self.bind_store()

    def counts(self):
        return tuple(self.c.execute('SELECT count(*) FROM p24_next.'+table).fetchone()[0]
                     for table in ('foundation_source_manifest','foundation_source_receipt'))

    def ledger(self):
        return self.c.execute("SELECT snapshot_id,receipt_id,received_at,receipt_time_basis,disposition,manifest_sha256 FROM p24_next.foundation_source_receipt ORDER BY snapshot_id,receipt_id").fetchall()

    def test_populated_upgrade_preserves_sealed_request_and_exact_legacy_receipt_facts(self):
        rows=[document()]
        sid=legacy_source(self.store,0,rows=rows)
        assessment=dict(contract_version='p24-scroll-capture.1',query_traversal_complete=False,
                        source_window_complete=False,source_finality='not_established',
                        source_claim_state='unverified_local_capture',
                        pages=[],slices=[],issues=['no_terminal_empty_page'])
        other=legacy_source(self.store,1,assessment=assessment,basis='producer_manifest')
        before=self.store.project([sid],event_cutoff='2026-10-20T07:40:00Z',
                                  knowledge_at='2026-10-20T07:45:00Z',mode='historical_revised')
        self.assertEqual(before['distinct_client_requests'],1)
        # The fixture deliberately still runs the pre-2H access schema here.
        with patch('p24_foundation.store.POLICY_VERSION','p24-access.2'):
            request=self.store.get_request(before['run_id'],'request-A',access_token=self.token)
        versions=self.c.execute('SELECT version_key,content_sha256 FROM p24_next.design_version ORDER BY version_key').fetchall()
        archive=self.store.vault.read(hashlib.sha256(batch(rows).original).hexdigest(),str(sid))
        initialize(self.c)
        self.assertEqual(self.counts(),(2,2))
        self.assertEqual(self.store.get_request(before['run_id'],'request-A',access_token=self.token),request)
        self.assertEqual(self.store.vault.read(hashlib.sha256(batch(rows).original).hexdigest(),str(sid)),archive)
        self.assertEqual(self.c.execute('SELECT version_key,content_sha256 FROM p24_next.design_version WHERE version_key<>ALL(%s) ORDER BY version_key',(['p24-foundation.2h.1','p24-foundation.2s.1','p24-foundation.2t.1','p24-foundation.2u.1'],)).fetchall(),versions)
        facts=self.c.execute("""SELECT r.snapshot_id,r.received_at=s.observed_at,r.input_bytes=o.byte_count,
            r.row_count=s.raw_event_count,r.interval_start=w.window_start,r.interval_end=w.window_end,
            r.source_digest=s.source_digest,r.manifest_sha256=m.manifest_sha256,r.receipt_time_basis,
            m.source_kind,m.safe_manifest,m.producer_authority,m.source_finality,m.source_window_complete
            FROM p24_next.foundation_source_receipt r JOIN p24_next.source_snapshot s USING(namespace_id,snapshot_id)
            JOIN p24_next.foundation_source_manifest m USING(namespace_id,snapshot_id)
            JOIN p24_next.raw_object o USING(namespace_id,snapshot_id)
            JOIN p24_next.source_window w USING(namespace_id,window_key) ORDER BY r.snapshot_id""").fetchall()
        self.assertTrue(all(all(row[1:8]) for row in facts))
        self.assertEqual(facts[0][8:10],('synthetic_fixture','legacy_unassessed'))
        self.assertEqual(facts[1][8:10],('producer_manifest_unverified','scroll_capture'))
        self.assertEqual(facts[1][10]['legacy_issues'],['no_terminal_empty_page'])
        self.assertTrue(all(row[11:]==('unverified','not_established',False) for row in facts))
        self.assertEqual(self.c.execute('SELECT state FROM p24_next.projection_run WHERE run_id=%s',(uuid.UUID(before['run_id']),)).fetchone(),('sealed',))

    def test_interruption_rolls_back_current_batch_and_reconnect_resumes_committed_prefix(self):
        for i in range(5):legacy_source(self.store,i)
        original=store_module._safe_source_manifest;calls=[]
        backfill=_backfill_source_manifest_receipts
        def interrupt(*args,**kwargs):
            calls.append(1)
            if len(calls)==4:raise FoundationError('synthetic_backfill_interrupt')
            return original(*args,**kwargs)
        with patch.object(store_module,'_safe_source_manifest',side_effect=interrupt),patch.object(
                store_module,'_backfill_source_manifest_receipts',side_effect=lambda c:backfill(c,batch_size=2)):
            with self.assertRaises(FoundationError) as caught:initialize(self.c)
        self.assertEqual(caught.exception.code,'synthetic_backfill_interrupt')
        self.assertEqual(len(calls),4)
        self.assertEqual(self.counts(),(2,2))
        prefix=self.ledger()
        self.assertEqual(self.c.execute('SELECT count(*) FROM p24_next.design_version').fetchone(),(12,))
        self.restart()
        initialize(self.c)
        self.assertEqual(self.counts(),(5,5))
        self.assertEqual(self.ledger()[:2],prefix)
        completed=self.ledger()
        initialize(self.c)
        self.assertEqual(self.ledger(),completed)

    def test_bounded_batch_budget_yields_and_repeated_work_does_not_duplicate_receipts(self):
        for i in range(5):legacy_source(self.store,i)
        with patch.object(store_module,'_backfill_source_manifest_receipts',return_value=0):initialize(self.c)
        self.assertEqual(_backfill_source_manifest_receipts(self.c,batch_size=2,max_batches=1),2)
        first=self.ledger();self.assertEqual(self.counts(),(2,2))
        self.restart()
        self.assertEqual(_backfill_source_manifest_receipts(self.c,batch_size=2,max_batches=1),2)
        self.assertEqual(self.ledger()[:2],first)
        self.assertEqual(_backfill_source_manifest_receipts(self.c,batch_size=2,max_batches=1),1)
        ledger=self.ledger();self.assertEqual(self.counts(),(5,5))
        self.assertEqual(_backfill_source_manifest_receipts(self.c),0)
        self.assertEqual(self.ledger(),ledger)

    def test_partial_manifest_without_receipt_is_repaired_without_rewriting_the_manifest(self):
        sid=legacy_source(self.store,0)
        with patch.object(store_module,'_backfill_source_manifest_receipts',return_value=0):initialize(self.c)
        manifest=dict(version='synthetic-existing-manifest',claims={'source_finality':'not_established'})
        digest=hashlib.sha256(canonical(manifest)).hexdigest()
        self.c.execute("""INSERT INTO p24_next.foundation_source_manifest
            (namespace_id,snapshot_id,source_digest,manifest_version,source_kind,manifest_sha256,safe_manifest)
            SELECT namespace_id,snapshot_id,source_digest,'synthetic-existing-manifest','legacy_unassessed',%s,%s
            FROM p24_next.source_snapshot WHERE snapshot_id=%s""",(digest,jsonb(manifest),sid))
        old=self.c.execute('SELECT * FROM p24_next.foundation_source_manifest').fetchall()
        self.assertEqual(_backfill_source_manifest_receipts(self.c),0)
        self.assertEqual(self.counts(),(1,1))
        self.assertEqual(self.c.execute('SELECT * FROM p24_next.foundation_source_manifest').fetchall(),old)
        self.assertEqual(self.ledger()[0][-1],digest)

    def test_database_rejects_manifest_and_receipt_update_or_delete(self):
        legacy_source(self.store,0);initialize(self.c)
        for table in ('foundation_source_manifest','foundation_source_receipt'):
            before=self.c.execute('SELECT * FROM p24_next.'+table).fetchall()
            for sql in ('UPDATE p24_next.'+table+' SET source_digest=source_digest',
                        'DELETE FROM p24_next.'+table):
                with self.subTest(sql=sql),self.assertRaises(psycopg.Error),self.c.transaction():
                    self.c.execute(sql)
                self.assertEqual(self.c.execute('SELECT * FROM p24_next.'+table).fetchall(),before)

    def test_missing_raw_object_fails_explicitly_and_rolls_back_the_new_manifest(self):
        legacy_source(self.store,0,omit_object=True)
        with self.assertRaises(FoundationError) as caught:initialize(self.c)
        self.assertEqual(caught.exception.code,'source_backfill_incomplete')
        self.assertEqual(self.counts(),(0,0))

    def test_missing_snapshot_metadata_cannot_be_silently_skipped(self):
        legacy_source(self.store,0,omit_metadata=True)
        with self.assertRaises(FoundationError) as caught:initialize(self.c)
        self.assertEqual(caught.exception.code,'source_backfill_incomplete')
        self.assertEqual(self.counts(),(0,0))

    def test_default_250_row_boundary_keeps_exactly_one_first_receipt_per_source(self):
        for i in range(251):legacy_source(self.store,i)
        initialize(self.c)
        self.assertEqual(self.counts(),(251,251))
        before=self.ledger();self.restart();initialize(self.c)
        self.assertEqual(self.ledger(),before)

    def test_identical_reingest_after_upgrade_adds_a_receipt_without_duplication_of_source(self):
        rows=[document()];sid=legacy_source(self.store,0,rows=rows);initialize(self.c)
        initial=self.ledger()
        reused=self.store.ingest(batch(rows),source_key='synthetic-legacy-0',
            interval_start='2026-10-20T07:25:00Z',interval_end='2026-10-20T07:45:00Z',
            observed_at='2026-10-20T07:41:00Z',receive_time_basis='synthetic_fixture')
        self.assertTrue(reused['reused']);self.assertEqual(reused['snapshot_id'],str(sid))
        self.assertEqual(self.counts(),(1,2))
        self.assertEqual([r for r in self.ledger() if r[4]=='accepted'],initial)
        self.assertEqual(self.c.execute('SELECT count(*) FROM p24_next.source_snapshot').fetchone(),(1,))
