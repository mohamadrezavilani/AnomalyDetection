"""D2-A/D2-B read-only telemetry and SQL path selection regression tests."""
import unittest
from unittest.mock import patch
from pathlib import Path
import tempfile

from p24_foundation.viewer_data import ViewerDB
from tools.viewer_pg_observer import numeric_delta,load_viewer_database
from tools.benchmark_viewer_pg_writes import _load,_seed_query,METHODS


class FakeCopy:
    def __init__(self,buffer,mode):self.buffer=buffer;self.mode=mode
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def __iter__(self):return iter([b'PGCOPY\n',b'HEADER'])
    def write(self,b):self.buffer.append(b)


class FakeCursor:
    def __init__(self,buffer,statements):self.buffer=buffer;self.statements=statements
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def copy(self,statement):
        self.statements.append(statement)
        return FakeCopy(self.buffer,statement)


class FakeConn:
    def __init__(self):self.buffer=[];self.statements=[]
    def cursor(self):return FakeCursor(self.buffer,self.statements)


class D2ABInstrumentationTests(unittest.TestCase):
    def setUp(self):
        self.db=ViewerDB.__new__(ViewerDB)
        self.db.conn=FakeConn();self.events=[]
        self.db.progress_callback=lambda event:self.events.append(event)
        self.sql=[]
        self.db.sql=lambda statement,params=():self.sql.append(statement)

    def test_copy_both_phases_recorded_without_payloads(self):
        self.db._copy_ingest_stage_into_table('viewer_stage_events','viewer_events','origin_key,version_key','origin_key,version_key')
        self.assertEqual(len(self.db.conn.statements),2)
        self.assertIn('ORDER BY origin_key,version_key',self.db.conn.statements[0])
        self.assertIn('FROM STDIN (FORMAT BINARY)',self.db.conn.statements[1])
        done=self.events[-1]
        self.assertEqual(done['stage'],'ingest_bulk_copy_completed')
        self.assertGreater(done['spool_bytes'],0)
        self.assertEqual(done['bytes_uploaded'],done['spool_bytes'])
        self.assertGreaterEqual(done['upload_and_finish_seconds'],0)
        self.assertTrue(all('password' not in str(x) for x in self.events))

    def test_insert_select_alternatives_keep_strict_pk_semantics(self):
        self.db._insert_ingest_stage_into_table('viewer_stage_events','viewer_events','origin_key,version_key','origin_key,version_key')
        self.db._insert_ingest_stage_into_table('viewer_stage_events','viewer_events','origin_key,version_key',None)
        self.assertIn('ORDER BY origin_key,version_key',self.sql[0])
        self.assertNotIn('ORDER BY',self.sql[1]);self.assertTrue(all('ON CONFLICT' not in q for q in self.sql))

    def test_regular_viewer_uses_copy_and_noncopy_tables_keep_conflict(self):
        self.db._ingest_stage_rows={'viewer_events':1,'viewer_raw_events':1,'viewer_links':1}
        self.db._ingest_timing={'staging_seconds':0.0}
        self.db._ingest_stage_details={'merge_seconds':0.0}
        copied=[]
        self.db._copy_ingest_stage_into_table=lambda stage,table,columns,order:copied.append(table)
        self.db._merge_ingest_stages()
        self.assertEqual(copied,['viewer_events','viewer_links'])
        self.assertTrue(any('ON CONFLICT' in q for q in self.sql))
        self.assertEqual([e['method'] for e in self.events if e['stage']=='ingest_merge_complete'],
                         ['copy_binary','insert_select','copy_binary'])

    def test_no_benchmark_override_in_production(self):
        self.assertFalse(hasattr(ViewerDB,'_qualification_final_write_method'))
        self.db._qualification_final_write_method='not_valid'
        self.db._ingest_stage_rows={'viewer_events':1}
        self.db._ingest_timing={'staging_seconds':0}
        self.db._ingest_stage_details={'merge_seconds':0}
        with self.assertRaisesRegex(ValueError,'invalid_qualification_final_write_method'):
            self.db._merge_ingest_stages()

    def test_read_only_observer_delta_reset_and_redacted_config_guard(self):
        self.assertEqual(numeric_delta({'a':4,'b':5},{'a':7,'b':2}),{'a':3,'b':None})
        with tempfile.TemporaryDirectory() as folder:
            cfg=Path(folder)/'viewer_config.local.py'
            cfg.write_text("DATABASE={'dbname':'pishkhan24_shadow'}\n",encoding='utf8')
            with self.assertRaisesRegex(ValueError,'observer_requires'):
                load_viewer_database(cfg)
            with self.assertRaisesRegex(ValueError,'requires_isolated'):
                _load(cfg)

    def test_synthetic_seed_uses_disjoint_origins_and_no_operational_rows(self):
        for table in ('viewer_events','viewer_links'):
            a,p=_seed_query(table,'history',20);b,p2=_seed_query(table,'new',20)
            self.assertIn('bench_history',a);self.assertIn('bench_new',b)
            self.assertIn("'h-origin-'",a);self.assertIn("'n-origin-'",b)
            self.assertEqual(p,(20,));self.assertEqual(p2,(20,))

if __name__=='__main__':unittest.main()
