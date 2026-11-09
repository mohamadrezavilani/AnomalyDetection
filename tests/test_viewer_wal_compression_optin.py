"""D2-B: immutable publication path and lossless WAL compression opt-in safety."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from p24_foundation.viewer_online import publish_capture, FIVE_NS
from tests.test_viewer_online import verified_file


class _ProbeDB:
    def __init__(self,method,sqlite=False):
        self._publication_wal_compression=method
        self.sqlite=sqlite;self.queries=[];self.events=[];self.rolled=False
        self.keys=type('Keys',(),{'fingerprint':'k'})()
        self.conn=self
    def write_lock(self):self.queries.append('acquire_transaction_lock')
    def sql(self,statement,params=()):self.queries.append(statement)
    def progress(self,stage,**extra):self.events.append((stage,extra))
    def one(self,*args,**kwargs):raise RuntimeError('stop_after_wal_setup')
    def rollback(self):self.rolled=True


class WalCompressionOptInTests(unittest.TestCase):
    def _attempt(self,db):
        with TemporaryDirectory() as temporary:
            path=verified_file(Path(temporary)/'empty.gz',[],0)
            return publish_capture(db,path,0,FIVE_NS)
    def test_no_opt_in_is_unchanged(self):
        db=_ProbeDB(None)
        with self.assertRaisesRegex(RuntimeError,'stop_after_wal_setup'):self._attempt(db)
        self.assertEqual(db.queries,['acquire_transaction_lock'])
        self.assertTrue(db.rolled)
    def test_explicit_lossless_compression_is_transaction_local(self):
        for method in ('pglz','lz4','zstd'):
            with self.subTest(method=method):
                db=_ProbeDB(method)
                with self.assertRaisesRegex(RuntimeError,'stop_after_wal_setup'):self._attempt(db)
                self.assertEqual(db.queries,['acquire_transaction_lock',
                    'SET LOCAL wal_compression = '+method])
                self.assertEqual(db.events[1],('publication_wal_compression',{'method':method}))
                self.assertTrue(db.rolled)
    def test_invalid_and_sqlite_cannot_apply_opt_in(self):
        for method,sqlite in (('off',False),('pglz',True)):
            db=_ProbeDB(method,sqlite)
            with self.assertRaisesRegex(ValueError,'invalid_viewer_wal_compression'):self._attempt(db)
            self.assertEqual(db.queries,['acquire_transaction_lock'])
            self.assertTrue(db.rolled)

if __name__=='__main__':unittest.main()
