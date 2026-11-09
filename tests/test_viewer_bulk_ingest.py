"""Batch boundaries preserve evidence revisions, rollback and lookup bounds."""
import copy
from pathlib import Path
import tempfile
import unittest

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from tests.test_viewer_online import verified_file
from tests.test_viewer_r6_service_journey import log


class BulkIngestTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);generate_keys(self.root/'keys')
        self.db=ViewerDB(sqlite_path=self.root/'viewer',keys_path=self.root/'keys')
        self.addCleanup(self.db.close);self.db.init()

    def rows(self,n):
        return [log(i,'request_'+str(i),'Services.v1/WaterBills Line:1',
                    'POST (G00000 | successful)') for i in range(n)]

    def test_cross_batch_duplicate_projection_and_material_revision(self):
        rows=self.rows(501)
        projected=dict(rows[0],_score=1)
        changed=dict(rows[0],RequestID='reassigned',message='POST (GD2016 | failed)')
        result=self.db.ingest([verified_file(self.root/'all.gz',rows+[copy.deepcopy(rows[0]),projected,changed])])[0]
        self.assertEqual((result['new_events'],result['duplicates'],result['conflicts']),(502,2,1))
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_capture_projections')['n'],1)
        self.db.rebuild()
        for request in ('request_0','reassigned'):
            self.assertEqual(self.db.lookup_request(request)['conflicted'],1)
        repeated=self.db.ingest([verified_file(self.root/'repeat.gz',[projected,rows[0],changed])])[0]
        self.assertEqual((repeated['new_events'],repeated['duplicates']),(0,3))

    def test_origin_lookup_uses_one_query_per_batch(self):
        queries=[];original=self.db.sql
        def trace(statement,params=()):
            if statement.startswith('SELECT origin_key,version_key,request_key FROM viewer_events'):
                queries.append(len(params))
            return original(statement,params)
        self.db.sql=trace
        result=self.db.ingest([verified_file(self.root/'many.gz',self.rows(1201))])[0]
        self.assertEqual(result['new_events'],1201)
        self.assertEqual(queries,[500,500,201])

    def test_bad_record_after_first_batch_rolls_back_every_event(self):
        rows=self.rows(501);rows[-1]['message']=None
        with self.assertRaisesRegex(ValueError,'message_type'):
            self.db.ingest([verified_file(self.root/'bad.gz',rows)],commit=False)
        for table in ('viewer_events','viewer_raw_events','viewer_files','viewer_event_captures'):
            self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM '+table)['n'],0)

    def test_closed_progress_console_cannot_fail_ingest(self):
        def closed(event):raise BrokenPipeError('closed')
        self.db.progress_callback=closed
        self.assertEqual(self.db.ingest([verified_file(self.root/'one.gz',self.rows(1))])[0]['status'],'IMPORTED')


if __name__=='__main__':unittest.main()
