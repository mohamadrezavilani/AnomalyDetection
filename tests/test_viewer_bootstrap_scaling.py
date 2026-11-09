"""Bootstrap scans once, refreshes heads once and retains atomic revisions."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB


def seed_requests(db,count):
    requests=[];actions=[]
    for n in range(count):
        key=f'{n:064x}';session=f'{n%31:064x}'
        requests.append((key,session,'assigned',n,n,n,'Services.v1/WaterBills Line:1',
                         'G00000',1,1,0,0,0,'unknown'))
        actions.append((key,session,'WaterBills','WaterBills','business','unknown',n,'success',
                        key,None,None,None,'{}'))
    db.many('INSERT INTO viewer_requests VALUES ('+','.join('?' for _ in range(14))+')',requests)
    db.many('INSERT INTO viewer_actions VALUES ('+','.join('?' for _ in range(13))+')',actions)
    db.conn.commit()


class BootstrapScalingTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name);generate_keys(root/'keys')
        self.db=ViewerDB(sqlite_path=root/'viewer',keys_path=root/'keys')
        self.addCleanup(self.db.close);self.db.init();seed_requests(self.db,1601)

    def test_full_bootstrap_reads_one_snapshot_and_refreshes_heads_once(self):
        queries=[];original=self.db.sql;refresh=self.db._refresh_semantic_session_heads
        def trace(sql,params=()):
            queries.append(sql);return original(sql,params)
        with patch.object(self.db,'sql',side_effect=trace),patch.object(self.db,'_refresh_semantic_session_heads',wraps=refresh) as heads:
            info=self.db.build_semantic_index(batch_size=50)
        self.assertEqual(info['request_candidates_scanned'],1601)
        self.assertEqual(heads.call_count,1)
        self.assertEqual(sum('AS previous_request_key' in sql for sql in queries),1)
        self.assertFalse(any('SELECT * FROM viewer_semantic_occurrences WHERE request_key IN' in sql for sql in queries))
        expected={f'{n%31:064x}':f'{n:064x}' for n in range(1601)}
        self.assertEqual({r['session_key']:r['request_key'] for r in self.db.all('SELECT * FROM viewer_semantic_session_heads')},expected)

    def test_rebuild_preserves_anchor_revisions_and_no_duplicate_transitions(self):
        self.db.build_semantic_index(batch_size=50)
        before=self.db.all('SELECT request_key,anchor_key,revision,state FROM viewer_semantic_occurrences ORDER BY request_key')
        info=self.db.build_semantic_index(batch_size=100)
        self.assertEqual(info['changed_anchors'],0)
        self.assertEqual(before,self.db.all('SELECT request_key,anchor_key,revision,state FROM viewer_semantic_occurrences ORDER BY request_key'))
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_semantic_transitions')['n'],1601)

    def test_incremental_session_move_and_withdrawal_refresh_once(self):
        self.db.build_semantic_index()
        self.db.sql("UPDATE viewer_actions SET category='support' WHERE action_key=?",(f'{1600:064x}',))
        self.db.sql('UPDATE viewer_requests SET session_key=? WHERE request_key=?',('f'*64,f'{1599:064x}'))
        keys=[f'{n:064x}' for n in range(1601)]
        refresh=self.db._refresh_semantic_session_heads
        with patch.object(self.db,'_refresh_semantic_session_heads',wraps=refresh) as heads:
            self.db.reconcile_semantic_requests(keys)
        self.assertEqual(heads.call_count,1)
        incremental=self.db.all('SELECT * FROM viewer_semantic_session_heads ORDER BY session_key')
        self.db.build_semantic_index()
        self.assertEqual(incremental,self.db.all('SELECT * FROM viewer_semantic_session_heads ORDER BY session_key'))

    def test_bootstrap_exception_rolls_back_all_batches_and_heads(self):
        self.db.build_semantic_index();before=self.db.all('SELECT * FROM viewer_semantic_session_heads ORDER BY session_key')
        self.db.sql("UPDATE viewer_actions SET category='support'");self.db.conn.commit()
        original=self.db._write_semantic_batch;calls=[0]
        def fail(rows,**kwargs):
            result=original(rows,**kwargs);calls[0]+=1
            if calls[0]==3:raise RuntimeError('controlled_bootstrap_failure')
            return result
        with patch.object(self.db,'_write_semantic_batch',side_effect=fail):
            with self.assertRaisesRegex(RuntimeError,'controlled_bootstrap_failure'):
                self.db.build_semantic_index(batch_size=50)
        self.assertEqual(before,self.db.all('SELECT * FROM viewer_semantic_session_heads ORDER BY session_key'))
        self.assertEqual(self.db.one("SELECT COUNT(*) AS n FROM viewer_semantic_occurrences WHERE state='active'")['n'],1601)

    def test_copy_stage_uses_bound_rows_without_committing(self):
        from contextlib import contextmanager
        rows=[('a','b',None,None,None,b'\x00\xff'),('c','d','r','s','ip',b'payload')]
        written=[];commands=[]
        class Cursor:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            @contextmanager
            def copy(self,statement):commands.append(statement);yield self
            def write_row(self,row):written.append(row)
        class Connection:
            def cursor(self):return Cursor()
            def commit(self):raise AssertionError('COPY must not commit')
        with patch.object(self.db,'conn',Connection()):
            self.db._copy_ingest_stage('viewer_stage_raw_events','origin_key,version_key,raw_request_id,raw_session_id,raw_ip,payload',rows)
        self.assertEqual(written,rows)
        self.assertEqual(commands,['COPY viewer_stage_raw_events (origin_key,version_key,raw_request_id,raw_session_id,raw_ip,payload) FROM STDIN'])


if __name__=='__main__':unittest.main()
