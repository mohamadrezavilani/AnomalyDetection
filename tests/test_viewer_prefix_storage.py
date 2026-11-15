"""Native identity equivalence, interrupted cutover, recovery and COPY A/B.

Only disposable native fixture databases are opened. The benchmark preserves
the same logged table, secondary indexes, rows and binary COPY transport.
"""
from hashlib import sha256
import json
import os
import statistics
import time
import unittest
from unittest.mock import patch

from p24_foundation import viewer_prefix_storage as prefix
from p24_foundation import viewer_storage_keys as legacy
from p24_foundation.viewer_online import FIVE_NS
from tests import test_viewer_minimal_pg as native
from tests.test_viewer_online import START,iso,snapshot
from tests.test_viewer_r6_service_journey import log,sql


def key(value):return sha256(str(value).encode()).hexdigest()
def nodes(plan):
    yield plan
    for child in plan.get('Plans',[]):yield from nodes(child)


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PG18 cluster not configured')
class NativePrefixStorageTests(unittest.TestCase):
    setUpClass=classmethod(native.NativeMinimalPublicationTests.setUpClass.__func__)
    tearDownClass=classmethod(native.NativeMinimalPublicationTests.tearDownClass.__func__)
    publish=native.NativeMinimalPublicationTests.publish

    def setUp(self):
        original=native.ViewerDB.init
        def baseline(db):
            db._qualification_legacy_evidence_indexes=True
            return original(db)
        with patch.object(native.ViewerDB,'init',baseline):
            native.NativeMinimalPublicationTests.setUp(self)

    def upgrade(self):self.db.conn.commit();prefix.ensure(self.db)

    def fixture(self,count=6000):
        links=[];identifiers=[];observations=[]
        for n in range(count):
            origin,version,request=key('o'+str(n)),key('v'+str(n)),key('r'+str(n//4))
            for field in range(3):
                links.append((origin,version,request,'domain-'+str(field),key('id'+str(n//4)+':'+str(field))))
                identifiers.append((origin,version,request,'pishkhan24','internal_payment','synthetic',
                    'field.'+str(field),'r5:'+key('i'+str(n)+':'+str(field)),'fixture'))
                observations.append((origin,version,request,n,'Core.v1/Fixture','axis-'+str(field),
                    'value-'+str(field),'field.'+str(field),'reported'))
        for table,rows in (('viewer_links',links),('viewer_contract_identifiers',identifiers),('viewer_contract_observations',observations)):
            self.db.many('INSERT INTO '+table+' VALUES('+','.join('?' for _ in rows[0])+')',rows)
        self.db.conn.commit()

    def rows(self):
        return {table:self.db.all('SELECT * FROM '+table+' ORDER BY '+','.join(keys)) for table,keys in legacy.KEYS.items()}

    def test_upgrade_keeps_full_rows_and_checkpoint_and_origin_probe_uses_the_unique_prefix(self):
        self.fixture();before=self.rows();state=self.db.one('SELECT * FROM viewer_live_state')
        self.upgrade();self.assertEqual(before,self.rows());self.assertEqual(state,self.db.one('SELECT * FROM viewer_live_state'))
        for name,table in prefix.INDEXES.items():
            keys=legacy.KEYS[table]
            status=prefix.index_status(self.db,name,table,(keys[:2],keys[2:]),unique=True)
            self.assertTrue(status['indisvalid'] and status['indisready'])
        for name in legacy.INDEXES:self.assertIsNone(self.db.one('SELECT to_regclass(?) AS present',(name,))['present'])
        query='SELECT * FROM viewer_links WHERE '+legacy.digest_sql(('origin_key','version_key'))+'='+legacy.FUNCTION+'(?,?) AND origin_key=? AND version_key=?'
        origin,version=key('o100'),key('v100')
        plan=self.db.one('EXPLAIN(FORMAT JSON) '+query,(origin,version,origin,version))['QUERY PLAN'][0]['Plan']
        self.assertIn('vli_prefix_key_v2',{p.get('Index Name') for p in nodes(plan)})
        self.assertEqual(len(self.db.all(query,(origin,version,origin,version))),3)
        self.db.conn.commit();prefix.ensure(self.db);legacy.ensure(self.db)
        self.assertEqual(before,self.rows())

    def test_interrupted_concurrent_build_keeps_old_indexes_and_restart_finishes_without_row_changes(self):
        self.fixture(40);before=self.rows();callback=self.db.progress_callback if hasattr(self.db,'progress_callback') else None
        def crash(event):
            if event['stage']=='prefix_index_ready':raise RuntimeError('controlled_prefix_interruption')
        self.db.progress_callback=crash
        with self.assertRaisesRegex(RuntimeError,'controlled_prefix_interruption'):self.upgrade()
        self.db.progress_callback=callback
        self.assertEqual(self.db.one('SELECT layout FROM viewer_storage_layout')['layout'],'compact_evidence_keys_v1')
        for name in legacy.INDEXES:self.assertIsNotNone(self.db.one('SELECT to_regclass(?) AS present',(name,))['present'])
        self.db.conn.commit();prefix.ensure(self.db)
        self.assertEqual(before,self.rows())

    def test_wrong_replacement_definition_blocks_cutover_and_preserves_existing_indexes(self):
        self.db.sql('CREATE INDEX vli_prefix_key_v2 ON viewer_links(request_key)');self.db.conn.commit()
        with self.assertRaisesRegex(ValueError,'prefix_index_definition_mismatch'):prefix.ensure(self.db)
        self.assertEqual(self.db.one('SELECT layout FROM viewer_storage_layout')['layout'],'compact_evidence_keys_v1')
        self.assertIsNotNone(self.db.one("SELECT to_regclass('vli_compact_key_v1') AS present")['present'])

    def test_repeated_identity_is_idempotent_but_forced_digest_collision_cannot_merge_witnesses(self):
        self.upgrade()
        self.db.sql("CREATE OR REPLACE FUNCTION public.viewer_key_digest_v1(VARIADIC parts text[]) RETURNS bytea LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $$ SELECT decode(repeat('00',32),'hex') $$")
        first=(key('o1'),key('v1'),key('r1'),'platform_payment',key('p1'))
        query='INSERT INTO viewer_links VALUES(?,?,?,?,?)'+legacy.conflict_clause(self.db,'viewer_links')
        self.db.sql(query,first);self.db.conn.commit()
        self.db.sql(query,first);self.db.conn.commit()
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_links')['n'],1);self.db.conn.commit()
        with self.assertRaises(Exception) as raised:
            self.db.sql(query,(key('o2'),key('v2'),key('r2'),'platform_payment',key('p2')))
        self.assertEqual(getattr(raised.exception,'sqlstate',None),'23505')
        self.db.conn.rollback();self.assertEqual(tuple(self.db.one('SELECT * FROM viewer_links').values()),first)

    def test_restore_and_reupgrade_preserve_full_values_and_the_original_conflict_target(self):
        self.fixture(40);before=self.rows();self.upgrade();self.db.conn.commit()
        prefix.restore(self.db)
        self.assertFalse(prefix.active(self.db));self.assertEqual(before,self.rows())
        for name in legacy.INDEXES:self.assertIsNotNone(self.db.one('SELECT to_regclass(?) AS present',(name,))['present'])
        for name in prefix.INDEXES:self.assertIsNone(self.db.one('SELECT to_regclass(?) AS present',(name,))['present'])
        row=next(iter(before['viewer_links']))
        self.db.sql('INSERT INTO viewer_links VALUES(?,?,?,?,?)'+legacy.conflict_clause(self.db,'viewer_links'),tuple(row.values()))
        self.db.conn.commit();prefix.ensure(self.db);self.assertEqual(before,self.rows())

    def test_migrated_live_publication_late_payment_and_revision_equal_full_rebuild(self):
        first=[log(1,'pay','Core.v1/WalletPayment Line:1','POST (G00000 | successful)'),
            log(2,'pay','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K'))]
        self.publish(first);before=snapshot(self.db);state=self.db.one('SELECT * FROM viewer_live_state')
        self.upgrade();self.assertEqual(before,snapshot(self.db));self.assertEqual(state,self.db.one('SELECT * FROM viewer_live_state'))
        callback=log(3,'callback','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K'))
        callback['@timestamp']=iso(START+FIVE_NS+1_000_000_000)
        self.publish([callback],START+FIVE_NS)
        changed=dict(first[1],RequestID='different',message=sql('ud_prc_paymentExists',paymentKey='K2'))
        self.publish([first[0],changed],mode='recheck')
        incremental=snapshot(self.db)
        self.db.rebuild();self.db.rebuild_payment_contract();self.db.build_semantic_index()
        self.assertEqual(incremental,snapshot(self.db))

    def test_binary_copy_balanced_ab_ba_retains_equal_rows_and_reports_index_io(self):
        # No throughput claim: this fixture is much smaller than the owner's
        # 14.8M links. Timing includes real binary COPY and its commit.
        db=self.db;columns='origin_key,version_key,request_key,link_domain,link_key'
        old='viewer_prefix_bench_old';new='viewer_prefix_bench_new';stage='viewer_prefix_bench_stage'
        for table in (old,new,stage):db.sql('CREATE TABLE '+table+' (LIKE viewer_links INCLUDING DEFAULTS)')
        generate="SELECT encode(sha256(('o'||n)::bytea),'hex'),encode(sha256(('v'||n)::bytea),'hex'),encode(sha256(('r'||(n/4))::bytea),'hex'),'domain-'||k,encode(sha256(('id'||(n/4)||':'||k)::bytea),'hex') FROM generate_series(1,?) n CROSS JOIN generate_series(1,3) k"
        db.sql('INSERT INTO '+stage+' '+generate,(40000,))
        order_old=legacy.digest_sql(legacy.KEYS['viewer_links']);order_new=prefix.ordered_key_sql('viewer_links')
        db.sql('INSERT INTO '+old+' SELECT * FROM '+stage+' ORDER BY '+order_old)
        db.sql('INSERT INTO '+new+' SELECT * FROM '+old+' ORDER BY ctid')
        db.sql('CREATE UNIQUE INDEX prefix_bench_old_key ON '+old+' ('+order_old+')')
        db.sql('CREATE INDEX prefix_bench_old_origin ON '+old+' ('+legacy.digest_sql(('origin_key','version_key'))+')')
        db.sql('CREATE UNIQUE INDEX prefix_bench_new_key ON '+new+' ('+','.join(prefix.expressions('viewer_links'))+')')
        for table in (old,new):
            db.sql('CREATE INDEX '+table+'_request ON '+table+'(request_key)')
            db.sql('CREATE INDEX '+table+'_value ON '+table+'(link_domain,link_key)')
        db.conn.commit();db.conn.autocommit=True
        try:
            db.sql('SET jit=off');db.sql("SET work_mem='64MB'")
            def io(table):
                db.sql('SELECT pg_stat_force_next_flush()');db.sql('SELECT pg_stat_clear_snapshot()')
                return db.one('SELECT COALESCE(SUM(idx_blks_read),0)::bigint AS reads,COALESCE(SUM(idx_blks_hit),0)::bigint AS hits FROM pg_statio_user_indexes WHERE relname=?',(table,))
            times={'old':[],'new':[]};counts={'old':[],'new':[]}
            for turn in range(4):
                db.sql('TRUNCATE TABLE '+stage)
                offset=40000+turn*5000
                db.sql('INSERT INTO '+stage+' '+generate.replace('generate_series(1,?)','generate_series(?,?)'),(offset+1,offset+5000))
                for label,table,order in ((('old',old,order_old),('new',new,order_new)) if turn%2==0 else (('new',new,order_new),('old',old,order_old))):
                    before=io(table);began=time.monotonic()
                    db._copy_ingest_stage_into_table(stage,table,columns,order)
                    times[label].append(time.monotonic()-began);after=io(table)
                    counts[label].append({k:after[k]-before[k] for k in before})
            self.assertEqual(db.one('SELECT COUNT(*) AS n FROM (TABLE '+old+' EXCEPT TABLE '+new+') d')['n'],0)
            self.assertEqual(db.one('SELECT COUNT(*) AS n FROM (TABLE '+new+' EXCEPT TABLE '+old+') d')['n'],0)
            sizes={table:db.one('SELECT pg_indexes_size(CAST(? AS regclass)) AS n',(table,))['n'] for table in (old,new)}
            print('PREFIX_NATIVE_AB='+json.dumps({'initial_origins':40000,'rows_per_batch':15000,'balanced_pairs':4,
                'seconds':times,'median_seconds':{k:statistics.median(v) for k,v in times.items()},
                'index_io_deltas':counts,'all_indexes_bytes':sizes,'full_rows_equal':True,
                'production_capacity':'NOT_MEASURED','index_definition_count':{'old':4,'new':3}}))
        finally:db.conn.autocommit=False


if __name__=='__main__':unittest.main()
