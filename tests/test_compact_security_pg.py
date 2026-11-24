import os
import unittest
from compact_behavior import FIVE, security
from compact_behavior.extract import behavior_id
from compact_ad.store import ChangedDuringAnalysis
from compact_product import case_selection
from compact_product.web import create_app
from tests.test_compact_extract import T, extract, row
from tests.test_compact_security import attempts
from tests import test_compact_product_pg as product_tests


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'), 'native PostgreSQL required')
class SecurityPostgresTests(unittest.TestCase):
    setUp = product_tests.CompactProductPostgresTests.setUp
    tearDown = product_tests.CompactProductPostgresTests.tearDown

    def publish(self, records, start=T):
        return self.db.publish('test',start,start+FIVE,extract(records),len(records))

    def test_both_groups_reach_operator_and_feedback_without_source_replay(self):
        from psycopg.types.json import Jsonb
        raw=attempts()+attempts('invalid_session',30)
        from compact_behavior.extract import iso
        raw.append(dict(row('same-ip-success', 'N/A', path='Core.v2/DeviceRegister',
                    at=iso(T+120*10**9)), IP='192.0.2.1'))
        self.publish(raw)
        # Simulate build-33 projections; the new analysis reads only retained
        # candidate payload/context primary keys, with no source write or rewind.
        s=self.config.source_schema
        self.db.conn.execute(f"UPDATE {s}.behaviors SET features=features-'security_attempt'")
        before=self.db.conn.execute(f'SELECT * FROM {s}.behaviors ORDER BY behavior_id').fetchall()
        self.db.step('test')
        after=self.db.conn.execute(f'SELECT * FROM {s}.behaviors ORDER BY behavior_id').fetchall()
        self.assertEqual(before,after)
        self.assertEqual(self.db.cursor('test'),T+FIVE)
        cases,_,truncated=case_selection.select(self.db.conn,self.config,'test',T,T+FIVE)
        self.assertFalse(truncated)
        self.assertEqual({c['domain'] for c in cases},{'session','network_attempts'})
        client=create_app(self.config,self.database,'test').test_client()
        landing=client.get('/incidents?date=2026-10-20&days=1').get_data(as_text=True)
        self.assertIn('تلاش پرتکرار با نشست نامعتبر',landing)
        for case in cases:
            response=client.get('/cases/'+case['case_id']+'?date=2026-10-20&days=1')
            self.assertEqual(response.status_code,200)
            finding=case['findings'][0]
            if case['domain']=='network_attempts':
                html=response.get_data(as_text=True)
                self.assertIn('رویدادهای هم‌زمان این IP',html)
                self.assertIn('G00002',html)
                self.assertIn('/feedback',html)
                self.assertNotIn('Core.v2/DeviceRegister',html)
                from compact_product.search import prepare_index
                prepare_index(self.db.conn,s)
                related=client.get('/cases/'+case['case_id']+'?date=2026-10-20&days=1&context='+finding['finding_id'])
                self.assertEqual(related.status_code,200)
                self.assertIn('Core.v2/DeviceRegister',related.get_data(as_text=True))
                self.assertEqual(finding['result']['observed'],30)
            self.db.conn.execute(f'INSERT INTO {self.config.ad_schema}.feedback(finding_id,finding_revision,verdict,note,recorded_at_ns) VALUES(%s,%s,%s,%s,%s)',
                                 (finding['finding_id'],finding['revision'],'FALSE_POSITIVE','fixture',1))
        self.assertFalse(case_selection.select(self.db.conn,self.config,'test',T,T+FIVE)[0])

    def test_context_correction_versions_security_but_ordinary_metadata_does_not(self):
        raw=attempts('invalid_session',30)
        self.publish(raw)
        self.db.step('test')
        work=self.db.snapshot('test',T)
        # Different IP at the same event timestamp makes attribution ambiguous.
        changed=[dict(r,IP='192.0.2.2') for r in raw]
        result=self.publish(changed)
        self.assertEqual(result['updated'],30)
        with self.assertRaises(ChangedDuringAnalysis):
            self.db.commit_analysis(work,[],.01)
        self.assertFalse(case_selection.select(self.db.conn,self.config,'test',T,T+FIVE)[0])
        self.db.step('test')
        self.assertFalse(case_selection.select(self.db.conn,self.config,'test',T,T+FIVE)[0])
        revision=self.db.conn.execute(f'SELECT revision FROM {self.config.source_schema}.behaviors LIMIT 1').fetchone()['revision']
        replay=self.publish([dict(r,UserAgent='new user agent') for r in changed])
        self.assertEqual(replay['updated'],0)
        self.assertEqual(self.db.conn.execute(f'SELECT revision FROM {self.config.source_schema}.behaviors LIMIT 1').fetchone()['revision'],revision)

    def test_access_refusals_are_known_even_for_old_features(self):
        from tools.Review_Compact_Unknowns import inventory
        raw=attempts(count=1)
        self.publish(raw)
        s=self.config.source_schema
        self.db.conn.execute(f"UPDATE {s}.behaviors SET features=features-'access_denied_attempt'-'security_attempt'")
        value=inventory(self.db.conn,s,'test')
        self.assertEqual(value['remaining_unknown'],0)

    def test_policy_migration_queues_existing_window_without_reset(self):
        self.publish(attempts())
        self.db.step('test')
        a=self.config.ad_schema
        self.db.conn.execute(f"UPDATE {a}.window_results SET summary=summary-'security'")
        self.db.close()
        self.db=product_tests.AnalysisStore(self.database,schema=self.config.source_schema,ad_schema=a)
        self.assertEqual(self.db.select_work('test'),T)
        self.db.step('test')
        self.assertEqual(self.db.cursor('test'),T+FIVE)
        self.assertEqual(self.db.conn.execute(f"SELECT summary->'security'->>'policy' AS policy FROM {a}.window_results").fetchone()['policy'],security.POLICY)

    def test_completed_policy_migration_does_not_reread_historical_json(self):
        from unittest.mock import Mock
        self.publish(attempts())
        self.db.step('test')
        self.assertIsNone(self.db.select_work('test'))
        real=self.db.conn
        measured=Mock(wraps=real)
        self.db.conn=measured
        try:
            for _ in range(10):self.assertIsNone(self.db.select_work('test'))
            queries=[str(call.args[0]) for call in measured.execute.call_args_list]
            self.assertFalse(any("summary->'security'" in sql for sql in queries))
        finally:
            self.db.conn=real

    def test_legacy_payload_and_ip_reads_stay_on_primary_keys_in_large_history(self):
        import json
        self.publish(attempts('invalid_session',30))
        s=self.config.source_schema
        self.db.conn.execute(f"UPDATE {s}.behaviors SET features=features-'security_attempt'")
        # No real evidence: unrelated retained rows emulate a large source.
        for table, column in [('behavior_payloads','state'),('request_context','context')]:
            self.db.conn.execute(f"INSERT INTO {s}.{table}(behavior_id,{column}) SELECT md5('unrelated-'||g), '{{}}'::jsonb FROM generate_series(1,100000) g")
            self.db.conn.execute(f'ANALYZE {s}.{table}')
        plan=self.db.conn.execute('EXPLAIN (ANALYZE,FORMAT JSON) '+security.input_sql(s),('test',T,T+FIVE)).fetchone()['QUERY PLAN']
        def nodes(v):
            if isinstance(v,dict):
                yield v
                for x in v.values():yield from nodes(x)
            elif isinstance(v,list):
                for x in v:yield from nodes(x)
        lookups=[n for n in nodes(plan) if n.get('Relation Name') in ('behavior_payloads','request_context')]
        self.assertEqual(len(lookups),2)
        self.assertTrue(all(n['Node Type']=='Index Scan' and 'behavior_id' in n.get('Index Cond','') for n in lookups))
        self.assertTrue(all(n['Actual Loops']==30 for n in lookups))


if __name__=='__main__':unittest.main()
