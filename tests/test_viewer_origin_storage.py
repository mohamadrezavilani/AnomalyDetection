"""Reversible key representation, index plans, interrupted upgrade and recovery."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import hashlib
import json
import os
import sys
import unittest
import zlib

from p24_foundation import viewer_origin_storage as origin
from tests import test_viewer_minimal_pg as native
from tests.test_viewer_online import START,FIVE_NS,snapshot,iso
from tests.test_viewer_r6_service_journey import log,sql


def key(value):return hashlib.sha256(str(value).encode()).hexdigest()


class OriginSqlTests(unittest.TestCase):
    def test_joins_keep_original_equality_and_all_bindings(self):
        query='SELECT b.payload FROM viewer_events e JOIN viewer_raw_events b ON b.origin_key=e.origin_key AND b.version_key=e.version_key WHERE e.request_key=%s'
        changed=origin.qualify(query)
        self.assertIn('b.origin_key=e.origin_key AND '+origin.key_sql('b.origin_key'),changed)
        self.assertIn(origin.key_sql('b.version_key')+'='+origin.key_sql('e.version_key'),changed)
        self.assertEqual(changed.count('%s'),1)
        self.assertEqual(origin.qualify(changed),changed)

    def test_literals_identifiers_comments_and_function_bodies_are_not_sql_operands(self):
        for query in ("SELECT 'a.origin_key=b.origin_key'",'SELECT "a.origin_key=b.origin_key"',
                'SELECT 1 -- a.origin_key=b.origin_key', 'SELECT 1 /* a.origin_key=b.origin_key */',
                'SELECT $$a.origin_key=b.origin_key$$','SELECT $body$a.origin_key=b.origin_key$body$'):
            with self.subTest(query=query):self.assertEqual(origin.qualify(query),query)

    def test_assignments_casts_json_expressions_and_three_part_names_remain_unchanged(self):
        for query in ('UPDATE viewer_events SET origin_key=source.origin_key',
                'SELECT 1 WHERE a.origin_key=b.origin_key::text',
                "SELECT 1 WHERE a.origin_key=b.body->>'origin'",
                'SELECT 1 WHERE public.viewer_events.origin_key=b.origin_key',
                'SELECT 1 WHERE a.origin_key=coalesce(b.origin_key,c.origin_key)'):
            with self.subTest(query=query):self.assertEqual(origin.qualify(query),query)

    def test_sqlite_legacy_and_binary_parameter_predicates_keep_parameter_counts(self):
        legacy=SimpleNamespace(_binary_origin_keys=False);binary=SimpleNamespace(_binary_origin_keys=True)
        self.assertEqual(origin.parameter_equal(legacy,'origin_key'),'origin_key=?')
        self.assertEqual(origin.origin_list(legacy,3),'origin_key IN (?,?,?)')
        self.assertEqual(origin.origin_list(binary,3).count('?'),3)
        self.assertEqual(origin.parameter_equal(binary,'origin_key').count('?'),1)
        self.assertIn('viewer_hmac_bytes_v1',origin.raw_conflict(binary))
        self.assertFalse(origin.active(SimpleNamespace(sqlite=True,_binary_origin_keys=True)))


def plan_nodes(plan):
    yield plan
    for child in plan.get('Plans',[]):yield from plan_nodes(child)


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PG18 cluster not configured')
class NativeOriginStorageTests(unittest.TestCase):
    setUpClass=classmethod(native.NativeMinimalPublicationTests.setUpClass.__func__)
    tearDownClass=classmethod(native.NativeMinimalPublicationTests.tearDownClass.__func__)
    publish=native.NativeMinimalPublicationTests.publish

    def setUp(self):
        initial=native.ViewerDB.init
        def legacy(db):
            db._qualification_storage_layout='compact_evidence_keys_v1'
            return initial(db)
        with patch.object(native.ViewerDB,'init',legacy):native.NativeMinimalPublicationTests.setUp(self)

    def fixture(self,count=1200):
        self.db.conn.commit()
        events=[];raw=[]
        for n in range(count):
            identity=(key('o'+str(n)),key('v'+str(n)))
            events.append((*identity,key('file'),'synthetic.gz',n,START+n,key('r'+str(n%512)),
                key('s'+str(n%256)),key('ip'),'ClientFixture.Call','provider',None,None))
            raw.append((*identity,'request-'+str(n),'session-'+str(n%256),'192.0.2.1',
                zlib.compress(json.dumps({'RequestID':'request-'+str(n),'value':n}).encode())))
        for table,rows in (('viewer_events',events),('viewer_raw_events',raw)):
            with self.db.conn.cursor() as cursor:
                with cursor.copy('COPY '+table+' FROM STDIN') as stream:
                    for row in rows:stream.write_row(row)
        self.db.conn.commit()
        return events,raw

    def rows(self):
        return {table:self.db.all('SELECT *,ctid::text AS tuple FROM '+table+' ORDER BY origin_key,version_key')
            for table in origin.INDEXES.values()}

    def upgrade(self):
        self.db.conn.commit();origin.ensure(self.db)

    def test_native_upgrade_preserves_rows_and_tuples_and_reduces_key_working_set(self):
        count=50000;self.fixture(count);before=self.rows()
        old=sum(self.db.one('SELECT pg_relation_size(CAST(? AS regclass)) AS n',(name,))['n']
            for name in ('viewer_events_pkey','viewer_raw_events_pkey','vei_origin_request'))
        self.upgrade()
        self.assertEqual(before,self.rows())
        new=sum(self.db.one('SELECT pg_relation_size(CAST(? AS regclass)) AS n',(name,))['n'] for name in origin.INDEXES)
        self.assertLess(new,old*.65)
        self.assertFalse(self.db.one("SELECT to_regclass('vei_origin_request') IS NOT NULL AS present")['present'])
        self.db.conn.commit();origin.ensure(self.db)
        self.assertEqual(before,self.rows())
        print('BINARY_ORIGIN_INDEX_BYTES '+json.dumps({'rows_per_table':count,'before':old,'after':new,'reduction_percent':round((1-new/old)*100,2)}))

    def test_native_mapping_is_injective_for_canonical_unusual_and_unicode_keys(self):
        self.upgrade()
        values=['0'*64,'a'*64,'A'*64,'f'*63,'f'*65,'','origin','é','e\u0301','\x01','نام']
        mapped=[self.db.one('SELECT '+origin.key_sql('?')+' AS value',(value,))['value'] for value in values]
        self.assertEqual(len(set(bytes(v) for v in mapped)),len(values))
        self.assertEqual(bytes(mapped[0]),b'\0'+bytes.fromhex(values[0]))
        self.assertEqual(len(mapped[1]),33)
        self.assertIsNone(self.db.one('SELECT '+origin.key_sql('?')+' AS value',(None,))['value'])
        for value in values:
            self.db.sql('INSERT INTO viewer_raw_events VALUES(?,?,?,?,?,?)',(value,'version',None,None,None,b'unchanged'))
            self.db.sql('INSERT INTO viewer_raw_events VALUES(?,?,?,?,?,?)'+origin.raw_conflict(self.db),(value,'version','ignored',None,None,b'changed'))
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_raw_events')['n'],len(values))
        self.assertTrue(all(bytes(r['payload'])==b'unchanged' for r in self.db.all('SELECT payload FROM viewer_raw_events')))

    def test_native_point_prefix_and_lateral_body_reads_use_binary_indexes(self):
        self.fixture(12000);self.upgrade()
        for table in origin.INDEXES.values():self.db.sql('ANALYZE '+table)
        def explain(query,params=()):
            return self.db.one('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+query,params)['QUERY PLAN'][0]['Plan']
        plan=explain('SELECT origin_key,version_key,request_key FROM viewer_events WHERE '+origin.origin_list(self.db,2),[key('o11'),key('o999')])
        self.assertTrue(any(n.get('Index Name')=='vei_binary_origin_v1' for n in plan_nodes(plan)))
        query='''SELECT body.payload FROM viewer_events e CROSS JOIN LATERAL
            (SELECT r.payload FROM viewer_raw_events r WHERE r.origin_key=e.origin_key
             AND r.version_key=e.version_key OFFSET 0) body WHERE e.request_key=? LIMIT 1'''
        plan=explain(query,(key('r11'),))
        self.assertTrue(any(n.get('Index Name')=='vre_binary_origin_v1' for n in plan_nodes(plan)))
        self.assertFalse(any(n.get('Node Type')=='Seq Scan' and n.get('Relation Name')=='viewer_raw_events' for n in plan_nodes(plan)))
        self.assertEqual(self.db.get_raw(key('o11'),key('v11'))['value'],11)

    def test_cold_expression_statistics_use_bounded_point_probes_for_large_batches(self):
        from p24_foundation import viewer_origin_storage as origin
        self.fixture(50000)
        self.db.sql('ANALYZE viewer_events');self.db.sql('ANALYZE viewer_raw_events')
        self.db.sql('CREATE FUNCTION '+origin.FUNCTION+'(key_text text) RETURNS bytea LANGUAGE SQL '
            'IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $origin$'+origin.BODY+'$origin$')
        for name,table in origin.INDEXES.items():
            self.db.sql('CREATE UNIQUE INDEX '+name+' ON '+table+'('+origin.key_sql('origin_key')+','+origin.key_sql('version_key')+')')
            self.assertEqual(self.db.one("SELECT COUNT(*) AS n FROM pg_stats WHERE schemaname='public' AND tablename=?",(name,))['n'],0)
        self.db._binary_origin_keys=True
        wanted=sorted([key('o'+str(n)) for n in range(1024)]+[key('missing'+str(n)) for n in range(1024)])
        old='SELECT origin_key,version_key,request_key FROM viewer_events WHERE '+origin.origin_list(self.db,len(wanted))
        old_plan=self.db.one('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+old,wanted)['QUERY PLAN'][0]
        query,params=origin.origin_lookup_sql(self.db,'viewer_events',('origin_key','version_key','request_key'),wanted)
        new_plan=self.db.one('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+query,params)['QUERY PLAN'][0]
        nodes=list(plan_nodes(new_plan['Plan']))
        self.assertFalse(any(n.get('Relation Name')=='viewer_events' and n['Node Type']=='Seq Scan' for n in nodes))
        self.assertTrue(any(n.get('Index Name')=='vei_binary_origin_v1' for n in nodes))
        self.assertEqual(sorted(self.db.all(old,wanted),key=lambda r:r['origin_key']),
            sorted(origin.lookup_origins(self.db,'viewer_events',wanted),key=lambda r:r['origin_key']))
        # The whole body table is not scanned for revision evidence either.
        query,params=origin.origin_lookup_sql(self.db,'viewer_raw_events',('origin_key','version_key','payload'),wanted)
        raw_plan=self.db.one('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+query,params)['QUERY PLAN'][0]
        self.assertTrue(any(n.get('Index Name')=='vre_binary_origin_v1' for n in plan_nodes(raw_plan['Plan'])))
        self.assertFalse(any(n.get('Relation Name')=='viewer_raw_events' and n['Node Type']=='Seq Scan' for n in plan_nodes(raw_plan['Plan'])))
        # A table owner does not need SELECT on restricted pg_statistic.
        import uuid
        from p24_foundation.viewer_storage_keys import ensure_expression_statistics
        role='p24_stats_'+uuid.uuid4().hex
        self.admin.execute('CREATE ROLE '+role+' NOLOGIN')
        self.addCleanup(lambda:self.admin.execute('DROP ROLE '+role))
        self.db.sql('ALTER TABLE viewer_events OWNER TO '+role)
        self.db.sql('SET ROLE '+role)
        try:
            self.assertFalse(self.db.one("SELECT has_table_privilege('pg_catalog.pg_statistic','SELECT') AS allowed")['allowed'])
            ensure_expression_statistics(self.db,{'vei_binary_origin_v1':'viewer_events'})
            self.assertEqual(self.db.one("SELECT COUNT(*) AS n FROM pg_stats WHERE schemaname='public' AND tablename='vei_binary_origin_v1'")['n'],2)
        finally:
            self.db.sql('RESET ROLE')
            self.db.conn.execute(self.pgsql.SQL('ALTER TABLE viewer_events OWNER TO {}').format(self.pgsql.Identifier(self.parameters['user'])))
        self.db.conn.commit();origin.ensure(self.db)
        for name in origin.INDEXES:
            self.assertEqual(self.db.one("SELECT COUNT(*) AS n FROM pg_stats WHERE schemaname='public' AND tablename=?",(name,))['n'],2)
        print('COLD_ORIGIN_PROBES '+json.dumps({'history_rows':50000,'batch':len(wanted),
            'old_root':old_plan['Plan']['Node Type'],'old_shared_blocks':old_plan['Plan']['Shared Hit Blocks']+old_plan['Plan']['Shared Read Blocks'],
            'new_root':new_plan['Plan']['Node Type'],'old_ms':old_plan['Execution Time'],'new_ms':new_plan['Execution Time']}))

    def test_cutover_reader_lock_rolls_back_and_the_next_upgrade_resumes(self):
        import psycopg
        self.fixture(200);before=self.rows();reader=psycopg.connect(**self.config)
        self.addCleanup(reader.close)
        def progress(event):
            if event['stage']=='origin_index_ready' and event['table']=='viewer_raw_events':
                reader.execute('SELECT * FROM viewer_events LIMIT 1')
        self.db.progress_callback=progress
        with self.assertRaises(psycopg.errors.LockNotAvailable):self.upgrade()
        self.assertEqual(before,self.rows())
        for table in origin.INDEXES.values():self.assertIsNotNone(origin._primary(self.db,table))
        reader.rollback();self.db.conn.commit();self.db.progress_callback=None;origin.ensure(self.db)
        self.assertEqual(before,self.rows())

    def test_raw_conflicts_restore_and_original_writer_are_data_preserving(self):
        self.fixture(100);before=self.rows();self.upgrade();self.db.conn.commit()
        origin.restore_original_keys(self.db)
        self.assertFalse(origin.active(self.db));self.assertEqual(before,self.rows())
        self.db.sql('INSERT INTO viewer_raw_events VALUES(?,?,?,?,?,?) ON CONFLICT(origin_key,version_key) DO NOTHING',
            (key('o1'),key('v1'),'ignored',None,None,b'changed'))
        self.assertEqual(before,self.rows())
        self.db.conn.commit();origin.restore_original_keys(self.db);self.assertEqual(before,self.rows())

    def test_late_payment_revision_and_global_conflict_match_full_rebuild(self):
        self.upgrade()
        first=[log(1,'pay','Core.v1/WalletPayment Line:1','POST (G00000 | successful)'),
            log(2,'pay','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K'))]
        self.publish(first)
        late=log(3,'callback','DBPath.x.ud_prc_paymentExists',sql('ud_prc_paymentExists',paymentKey='K'))
        late['@timestamp']=iso(START+FIVE_NS+1_000_000_000)
        self.publish([late],START+FIVE_NS)
        changed=dict(first[1],RequestID='another-owner')
        self.publish([first[0],changed],mode='recheck')
        before=snapshot(self.db)
        self.db.rebuild();self.db.rebuild_payment_contract();self.db.build_semantic_index()
        self.assertEqual(before,snapshot(self.db))
        self.assertEqual(self.db.lookup_request('pay')['conflicted'],1)

    def test_native_web_query_timeout_cancels_only_its_reader_and_returns_unavailable(self):
        import time
        from p24_foundation.viewer_ui import create_viewer_app
        seen=[]
        def slow(db,origin_key,version_key):
            seen.append(db.one("SELECT current_setting('application_name') AS app,current_setting('transaction_read_only') AS readonly,current_setting('max_parallel_workers_per_gather') AS parallel"))
            db.one('SELECT pg_sleep(3)')
        with patch.object(native.ViewerDB,'get_raw',slow):
            app=create_viewer_app({'config':self.config,'keys_path':self.keys})
            began=time.monotonic()
            with app.test_client() as client:response=client.get('/evidence/'+key('o')+'/'+key('v'))
        self.assertEqual(response.status_code,503)
        self.assertLess(time.monotonic()-began,4)
        self.assertEqual(seen,[{'app':'P24.Viewer.web','readonly':'on','parallel':'0'}])
        self.assertEqual(self.db.one("SELECT COUNT(*) AS n FROM pg_stat_activity WHERE datname=current_database() AND application_name='P24.Viewer.web'")['n'],0)

    def test_read_only_ad_bridge_uses_the_installed_binary_layout(self):
        import psycopg
        from psycopg.rows import dict_row
        project=Path(__file__).resolve().parents[1]
        sys.path.insert(0,str(project/'AnomalyDetection'))
        from anomaly_detection.pg_source import BudgetQuery
        from anomaly_detection.viewer_bridge import reader
        self.fixture(100);self.upgrade();self.db.conn.commit()
        with psycopg.connect(**self.config,row_factory=dict_row,autocommit=True,
                options='-c default_transaction_read_only=on -c statement_timeout=2000') as raw:
            q=BudgetQuery(raw,project=project)
            facade=reader(project,q)
            self.assertTrue(facade._binary_origin_keys)
            self.assertEqual(facade.get_raw(key('o11'),key('v11'))['value'],11)
            self.assertEqual(q("SELECT current_setting('transaction_read_only') AS state",cap=1)[0]['state'],'on')
