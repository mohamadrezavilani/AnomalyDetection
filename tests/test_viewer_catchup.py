"""Writer-only resource limits, WAL byte evidence and native crash/retry."""
from pathlib import Path
from types import SimpleNamespace
import json
import subprocess
import sys
import os
import unittest
from viewer_performance import Run_Viewer_Catchup as profile
from tests import test_viewer_minimal_pg as native
from tests.test_viewer_online import START,FIVE_NS,snapshot,iso,verified_file
from tests.test_viewer_r6_service_journey import log,sql


class ResourceTests(unittest.TestCase):
    def test_available_memory_controls_the_profile_without_requiring_a_large_server(self):
        for available,expected in ((8,{'work_mem':'64MB','temp_buffers':'128MB'}),
                (3,{'work_mem':'16MB','temp_buffers':'64MB'}),(1,{})):
            self.assertEqual(profile.memory_limits({'total_bytes':32*profile.GIB,'available_bytes':available*profile.GIB}),expected)
        self.assertEqual(profile.memory_limits({'total_bytes':profile.GIB,'available_bytes':9*profile.GIB}),{})
    def test_only_allowlisted_session_resources_can_change(self):
        original={'dbname':'p24_design_viewer','options':'-c statement_timeout=5000'}
        actual=profile.connection_options(original,{'work_mem':'64MB','temp_buffers':'128MB','wal_compression':'lz4'})
        self.assertEqual(original,{'dbname':'p24_design_viewer','options':'-c statement_timeout=5000'})
        self.assertIn('statement_timeout=5000',actual['options'])
        self.assertIn('wal_compression=lz4',actual['options'])
        for overrides in ({'fsync':'off'},{'synchronous_commit':'off'},{'work_mem':'8GB'}):
            with self.assertRaises(ValueError):profile.connection_options(original,overrides)
        with self.assertRaises(ValueError):profile.connection_options({'dbname':'postgres'},{})
    def test_unsupported_compression_falls_back_and_missing_privilege_keeps_current_mode(self):
        class Error(Exception):
            def __init__(self,code):self.sqlstate=code
        class Transaction:
            def __enter__(self):return self
            def __exit__(self,*args):return False
        class Connection:
            def __init__(self,fail):self.fail=fail;self.selected=[]
            def transaction(self):return Transaction()
            def execute(self,query,params=()):
                if params:
                    self.selected.append(params[0])
                    if params[0] in ('zstd','lz4'):raise Error(self.fail)
                return SimpleNamespace(fetchone=lambda:{'value':'off'})
        connection=Connection('0A000');self.assertEqual(profile.supported_compression(connection),'pglz')
        self.assertEqual(connection.selected,['zstd','lz4','pglz'])
        connection=Connection('42501');self.assertIsNone(profile.supported_compression(connection))
        self.assertEqual(connection.selected,['zstd'])
        with self.assertRaises(Error):profile.supported_compression(Connection('08006'))


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PG18 cluster not configured')
class NativeCatchupTests(unittest.TestCase):
    setUpClass=classmethod(native.NativeMinimalPublicationTests.setUpClass.__func__)
    tearDownClass=classmethod(native.NativeMinimalPublicationTests.tearDownClass.__func__)
    setUp=native.NativeMinimalPublicationTests.setUp
    publish=native.NativeMinimalPublicationTests.publish

    def before_and_overrides(self):
        import psycopg
        from psycopg.rows import dict_row
        with psycopg.connect(**self.config,row_factory=dict_row,autocommit=True) as conn:
            before={r['name']:r for r in conn.execute(profile.SETTINGS_SQL,(list(profile.NAMES),)).fetchall()}
            compression=profile.supported_compression(conn)
            self.assertEqual(conn.execute("SELECT current_setting('wal_compression') AS value").fetchone()['value'],before['wal_compression']['setting'])
        return before,profile.choose_overrides(before,{'available_bytes':8*profile.GIB,'total_bytes':32*profile.GIB},compression)

    def test_actual_profile_preserves_late_payment_rebuild_and_crash_retry(self):
        before,overrides=self.before_and_overrides();notices=[]
        from p24_foundation import viewer_data
        first=[log(1,'pay','Core.v1/WalletPayment Line:1','POST (G00000 | successful)'),
            log(2,'pay','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K'))]
        self.publish(first);self.db.close()
        original=viewer_data.ViewerDB.__init__
        with profile.activate_profile(viewer_data,before,overrides,notice=notices.append):
            self.db=viewer_data.ViewerDB(config=self.config,keys_path=self.keys);self.addCleanup(self.db.close)
            late=log(3,'callback','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K'))
            late['@timestamp']=iso(START+FIVE_NS+1_000_000_000)
            before_rows=snapshot(self.db);before_state=self.db.one('SELECT * FROM viewer_live_state');self.db.conn.rollback()
            path=verified_file(self.root/'crash-catchup.gz',[late],START+FIVE_NS)
            program=("import json,sys; from tests.test_viewer_minimal_pg import crash_publish; "
                "a=json.load(sys.stdin); crash_publish(a['config'],a['keys'],a['path'],a['start'],'after_relations')")
            child=subprocess.run([sys.executable,'-B','-c',program],
                input=json.dumps({'config':profile.connection_options(self.config,overrides),
                    'keys':str(self.keys),'path':str(path),'start':START+FIVE_NS}),
                text=True,capture_output=True,timeout=20,cwd=Path(__file__).resolve().parents[1])
            self.assertEqual(child.returncode,73,child.stderr)
            self.assertEqual(before_rows,snapshot(self.db));self.assertEqual(before_state,self.db.one('SELECT * FROM viewer_live_state'))
            self.db.conn.rollback();self.publish([late],START+FIVE_NS)
            expected=snapshot(self.db)
            self.db.rebuild();self.db.rebuild_payment_contract();self.db.build_semantic_index()
            self.assertEqual(expected,snapshot(self.db))
            self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_receipts')['n'],2)
        self.assertIs(viewer_data.ViewerDB.__init__,original)
        self.assertTrue(notices);self.assertEqual(notices[0]['status'],'VIEWER_CATCHUP_PROFILE_VERIFIED')
        self.assertFalse(notices[0]['durability_flags_changed']);self.assertFalse(notices[0]['global_settings_modified'])
        self.assertEqual(notices[0]['settings']['work_mem']['setting'],str(64*1024))
        self.assertEqual(notices[0]['settings']['temp_buffers']['setting'],str(128*1024**2//8192))

    def test_native_wal_compression_reduces_full_page_bytes_for_equal_random_index_inserts(self):
        before,overrides=self.before_and_overrides();compression=overrides.get('wal_compression',before['wal_compression']['setting'])
        self.assertIn(compression,('lz4','pglz','zstd'))
        for name in ('catchup_off','catchup_packed'):
            self.db.sql('CREATE TABLE '+name+'(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            self.db.sql("INSERT INTO "+name+" SELECT md5('seed'||n)||md5('other'||n),repeat('fixture',4) FROM generate_series(1,50000) n")
        self.db.conn.commit();self.db.sql('CHECKPOINT');self.db.conn.commit()
        measurements={}
        for name,method in (('catchup_off','off'),('catchup_packed',compression)):
            self.db.sql('SET LOCAL wal_compression='+method)
            plan=self.db.one("EXPLAIN (ANALYZE,BUFFERS,WAL,FORMAT JSON) INSERT INTO "+name+
                " SELECT md5('new'||n)||md5('revision'||n),repeat('fixture',4) FROM generate_series(1,10000) n")['QUERY PLAN'][0]
            measurements[name]={'wal_bytes':plan['Plan']['WAL Bytes'],'full_page_images':plan['Plan']['WAL FPI'],'execution_ms':plan['Execution Time']}
            self.db.conn.commit()
        self.assertEqual(self.db.all('SELECT * FROM catchup_off EXCEPT SELECT * FROM catchup_packed'),[])
        self.assertEqual(self.db.all('SELECT * FROM catchup_packed EXCEPT SELECT * FROM catchup_off'),[])
        self.assertGreater(measurements['catchup_off']['full_page_images'],100)
        self.assertLess(measurements['catchup_packed']['wal_bytes'],measurements['catchup_off']['wal_bytes']*.90)
        print('CATCHUP_WAL_BYTES '+json.dumps({'compression':compression,'measurements':measurements}))


if __name__=='__main__':unittest.main()
