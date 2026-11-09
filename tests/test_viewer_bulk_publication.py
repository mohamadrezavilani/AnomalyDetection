"""Bulk native transport and request-scoped reconstruction preserve evidence."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from tests.test_viewer_online import START,FIVE_NS,verified_file,publish_capture,snapshot
from tests.test_viewer_r6_service_journey import log


class BulkPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);generate_keys(self.root/'keys')
        self.db=ViewerDB(sqlite_path=self.root/'db',keys_path=self.root/'keys');self.addCleanup(self.db.close)
        self.db.init();self.db.init_semantic_index()

    def test_binary_copy_preserves_opaque_bytes_and_bounded_write_chunks_without_commit(self):
        blocks=[b'PGCOPY\n\xff\r\n\x00',b'\x00\x01\xff'*800000,b'\xff\xff']
        sent=[];commands=[]
        class Stream:
            def __iter__(self):return iter(blocks)
            def write(self,block):sent.append(block)
        class Cursor:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            @contextmanager
            def copy(self,statement):commands.append(statement);yield Stream()
        class Connection:
            def cursor(self):return Cursor()
            def commit(self):raise AssertionError('Publication owns commit')
        with patch.object(self.db,'conn',Connection()):
            self.db._copy_ingest_stage_into_table('viewer_stage_events','viewer_events','origin_key,version_key','origin_key,version_key')
        self.assertEqual(b''.join(sent),b''.join(blocks))
        self.assertLessEqual(max(map(len,sent)),1024*1024)
        self.assertTrue(commands[0].endswith('TO STDOUT (FORMAT BINARY)'))
        self.assertEqual(commands[1],'COPY viewer_events (origin_key,version_key) FROM STDIN (FORMAT BINARY)')

    def test_scoped_outcomes_reuse_only_impacted_requests_including_older_window_evidence(self):
        rows=[log(i+1,'r'+str(i),'Services.v1/ElectricBills Line:1','POST (GD2016 | unavailable)') for i in range(200)]
        self.db.ingest([verified_file(self.root/'history.gz',rows)]);self.db.rebuild()
        key=self.db.lookup_request('r4')['request_key'];before=snapshot(self.db)
        queries=[];original=self.db.sql
        def trace(statement,params=()):queries.append(statement);return original(statement,params)
        with patch.object(self.db,'sql',side_effect=trace):self.db.rebuild(request_keys=[key])
        self.assertEqual(snapshot(self.db),before)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_projection_events')['n'],1)
        outcome_queries=[q for q in queries if 'e.observation LIKE' in q or "e.observation IN ('paid_true'" in q]
        self.assertEqual(len(outcome_queries),2)
        self.assertTrue(all('FROM viewer_projection_events e' in q for q in outcome_queries))
        # Retain the global version-conflict exclusion; a scope must not
        # re-admit an origin whose other version belongs to another request.
        self.assertTrue(all('FROM viewer_events bad' in q for q in outcome_queries))
