"""C6 is an isolated storage experiment, not a production Viewer backend."""
from contextlib import contextmanager
import hashlib
import multiprocessing
import os
import unittest
import uuid

from viewer_performance.history_segments import IndexedBaseline,BuiltSegments,check_rows
from tests import test_viewer_contract_fetch_once as native_fixture


def token(value):return hashlib.sha256(value.encode()).digest()


def changes(count=8):
    result=[]
    for publication in (1,2,3):
        rows=[]
        for n in range(count):
            request=token('request-'+str(publication)+'-'+str(n));origin=token('origin-'+str(publication)+'-'+str(n))
            version=token('version-'+str(publication)+'-'+str(n));actor=token('actor-'+str(n%7))
            for kind in (1,2,3):
                key=origin+version if kind==1 else token('key-'+str(kind)+'-'+str(publication)+'-'+str(n))
                rows.append((True,(kind,key,publication,request,actor,origin,version,b'full-evidence-body-'+bytes([n%255])*256)))
        # A request crosses boundaries and its payment state changes. Both
        # raw origin/version witnesses remain, including the rival request.
        rows.append((publication==1,(4,token('multi-window-request'),publication,token('old-request'),
            token('actor-old'),None,None,b'semantic-revision-'+str(publication).encode())))
        rows.append((True,(5,token('transition-'+str(publication)),publication,token('old-request'),
            token('actor-old'),token('shared-origin'),token('material-'+str(publication)),b'late-payment-link')))
        if publication==1:rows.append((True,(6,token('operator-feedback'),publication,None,None,None,None,b'keep-human-decision')))
        result.append(rows)
    return result


def killed_prepare(config,rows,point):
    import psycopg
    raw=psycopg.connect(**config)
    store=BuiltSegments.__new__(BuiltSegments);store.raw=raw
    store.prepare(1,rows,fault=lambda stage:os._exit(73) if stage==point else None)
    os._exit(74)


class StorageContracts(unittest.TestCase):
    def test_existing_product_database_is_refused_before_any_ddl(self):
        class Connection:
            info=type('Info',(),dict(dbname='p24_design_viewer'))()
            def execute(self,*args):raise AssertionError('must not execute')
        for kind in (IndexedBaseline,BuiltSegments):
            with self.assertRaisesRegex(ValueError,'qualification'):kind(Connection())

    def test_batch_budgets_and_full_key_duplicates_are_explicit(self):
        rows=changes(1)[0]
        self.assertGreater(check_rows(rows),0)
        with self.assertRaisesRegex(ValueError,'duplicate'):check_rows([rows[0],rows[0]])
        with self.assertRaisesRegex(ValueError,'row_budget'):check_rows([rows[0]]*200001)


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PG18 not configured')
class NativeSegments(unittest.TestCase):
    setUpClass=classmethod(native_fixture.NativeContractFetchTests.setUpClass.__func__)
    tearDownClass=classmethod(native_fixture.NativeContractFetchTests.tearDownClass.__func__)

    @contextmanager
    def database(self,kind):
        import psycopg
        name='p24_design_segments_'+uuid.uuid4().hex[:16]+'_qualification'
        self.admin.execute(self.pgsql.SQL('CREATE DATABASE {}').format(self.pgsql.Identifier(name)))
        raw=psycopg.connect(**self.parameters,dbname=name)
        try:yield kind(raw),dict(self.parameters,dbname=name)
        finally:
            raw.close();self.admin.execute(self.pgsql.SQL('DROP DATABASE {}').format(self.pgsql.Identifier(name)))

    def test_postload_indexes_and_all_five_minute_boundaries_match(self):
        batches=changes();rows=sum(batches,[])
        with self.database(IndexedBaseline) as (baseline,_),self.database(BuiltSegments) as (candidate,_):
            receipt=candidate.prepare(1,rows)
            self.assertGreater(receipt['index_build_and_validation_seconds'],0)
            self.assertGreater(receipt['global_directory_seconds'],0)
            self.assertEqual(candidate.snapshot(),[]);candidate.raw.rollback()
            for publication,changed in enumerate(batches,1):
                baseline.publish(publication,changed);candidate.publish(publication)
                self.assertEqual(baseline.snapshot(),candidate.snapshot())
                baseline.raw.rollback();candidate.raw.rollback()
            self.assertEqual(candidate.raw.execute('SELECT body FROM segment_rows WHERE kind=6').fetchone()[0],b'keep-human-decision')

    def test_real_process_kills_during_load_build_and_both_sides_of_prepare_commit(self):
        rows=sum(changes(1),[])
        for point,prepared in (('after_load',False),('after_indexes',False),('before_prepare_commit',False),('after_prepare_commit',True)):
            with self.subTest(point=point),self.database(BuiltSegments) as (candidate,config):
                child=multiprocessing.get_context('spawn').Process(target=killed_prepare,args=(config,rows,point))
                child.start();child.join(30)
                if child.is_alive():child.kill();child.join();self.fail('segment child timed out')
                self.assertEqual(child.exitcode,73)
                self.assertEqual(candidate.snapshot(),[]);candidate.raw.rollback()
                saved=candidate.raw.execute('SELECT COUNT(*) FROM segments').fetchone()[0];candidate.raw.rollback()
                self.assertEqual(saved,int(prepared))
                receipt=candidate.prepare(1,rows)
                if prepared:self.assertEqual(receipt['status'],'REUSED_PREPARED_SEGMENT')
                candidate.publish(1);self.assertTrue(candidate.snapshot())

    def test_global_key_conflicts_rollback_and_future_updates_never_replace_the_past(self):
        batches=changes(1)
        with self.database(BuiltSegments) as (candidate,_):
            candidate.prepare(1,batches[0]);candidate.publish(1)
            before=candidate.snapshot();candidate.raw.rollback()
            candidate.prepare(2,batches[1]);self.assertEqual(candidate.snapshot(),before);candidate.raw.rollback()
            with self.assertRaises(Exception):candidate.prepare(3,[(True,tuple([r[0],r[1],3,*r[3:]])) for _,r in batches[0]])
            self.assertEqual(candidate.snapshot(),before)

    def test_empty_window_preserves_a_real_publication_boundary(self):
        with self.database(BuiltSegments) as (candidate,_):
            candidate.prepare(1,[],first_publication=1,last_publication=3)
            for sequence in (1,2,3):candidate.publish(sequence);self.assertEqual(candidate.snapshot(),[]);candidate.raw.rollback()

    def test_open_repeatable_read_snapshot_survives_build_attach_and_visibility_commits(self):
        import psycopg
        with self.database(BuiltSegments) as (candidate,config):
            with psycopg.connect(**config,autocommit=True) as reader:
                reader.execute('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
                old=BuiltSegments.__new__(BuiltSegments);old.raw=reader
                self.assertEqual(old.snapshot(),[])
                candidate.prepare(1,sum(changes(1),[]));candidate.publish(1)
                self.assertEqual(old.snapshot(),[])
                reader.execute('ROLLBACK');self.assertTrue(old.snapshot())


if __name__=='__main__':unittest.main()
