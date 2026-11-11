"""Real queue/CAS tests on disposable PostgreSQL, never the product database."""
from contextlib import ExitStack
import os
import unittest
import uuid
from unittest.mock import patch

from anomaly_detection import FIVE_NS
from anomaly_detection import scenario_store as scenarios
from anomaly_detection.product_store import ProductStore
from anomaly_detection.snapshot import canonical,digest

TARGET=100*FIVE_NS


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native AD test cluster not configured')
class NativeScenarioInvalidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        cls.psycopg=psycopg;cls.sql=sql
        cls.params={'host':os.environ['P24_DELTA_PG_HOST'],'port':int(os.environ.get('P24_DELTA_PG_PORT','5432')),
                    'user':os.environ.get('P24_DELTA_PG_USER','postgres'),'connect_timeout':3}
        cls.admin=psycopg.connect(**cls.params,dbname='postgres',autocommit=True)

    @classmethod
    def tearDownClass(cls):cls.admin.close()

    def setUp(self):
        from psycopg.rows import dict_row
        self.name='p24_design_adperf_'+uuid.uuid4().hex
        self.admin.execute(self.sql.SQL('CREATE DATABASE {}').format(self.sql.Identifier(self.name)))
        self.addCleanup(lambda:self.admin.execute(self.sql.SQL('DROP DATABASE {}').format(self.sql.Identifier(self.name))))
        self.raw=self.psycopg.connect(**self.params,dbname=self.name,autocommit=True,row_factory=dict_row)
        self.addCleanup(self.raw.close)
        self.raw.execute('CREATE SCHEMA anomaly_detection')
        self.store=ProductStore(self.raw)
        self.store.initialize();self.store._history_floor_ns=0

    def job(self,key='one',**values):
        row=dict(scope_key=key,kind='canonical_traffic',entity_key='S',service_path='S',target_ns=TARGET,
                 version=7,processed_version=0,dirty=True,due_ns=0,claimed_version=0)
        row.update(values)
        self.raw.execute('INSERT INTO anomaly_detection.adp_scenario_jobs('+','.join(row)+') VALUES('+','.join(['%s']*len(row))+')',tuple(row.values()))

    def read(self,key='one'):
        return self.raw.execute('SELECT * FROM anomaly_detection.adp_scenario_jobs WHERE scope_key=%s',(key,)).fetchone()

    def evaluate(self,hook=None):
        def traffic(service,target,current,past):
            if hook:hook()
            return [{'family':'service_volume','status':'INSUFFICIENT_DATA','observed':current['requests']}]
        with ExitStack() as stack:
            stack.enter_context(patch('anomaly_detection.scenario_store.volume_history',return_value=[]))
            stack.enter_context(patch('anomaly_detection.scenario_models.traffic',side_effect=traffic))
            stack.enter_context(patch('anomaly_detection.cases.replace_scope'))
            stack.enter_context(patch('anomaly_detection.cases.normal_observations'))
            return scenarios.process_one(self.store,TARGET+FIVE_NS)

    def population(self,count):
        self.raw.execute('DELETE FROM anomaly_detection.adp_population')
        body={'start_ns':TARGET,'executions':count,'sessions':1,'covered':True}
        self.raw.execute('INSERT INTO anomaly_detection.adp_population VALUES(%s,%s,%s,%s)',
                         ('S',TARGET,canonical(body),digest(body)))

    def window_packet(self,generation=1,revision=1):
        source={'namespace':'viewer:fixture','stream_key':'fixture','keys_fingerprint':'fixture',
                'generation':generation,'semantic_generation':generation,'captured_at_ns':TARGET+generation*FIVE_NS,
                'retention_cutoff_ns':0,'source_finality':'not_established'}
        row={'request_key':'a'*64,'anchor_key':'ba1:'+'a'*64,'session_key':'b'*64,'request_session_key':'b'*64,
             'anchor_ns':TARGET+1,'root_call':'Services.v1/Fixture','root_code':'G00000','state':'active',
             'kind':'service_execution','revision':revision,'identity_state':'assigned','conflicted':False}
        return {'source':source,'target_ns':TARGET,'stamp':'stamp-'+str(generation),
                'available':True,'rows':[row],'has_more':False}

    def test_pending_burst_avoids_250000_redundant_row_updates(self):
        count=5000;repeats=50
        self.raw.execute("INSERT INTO anomaly_detection.adp_scenario_jobs(scope_key,kind,entity_key,service_path,target_ns,version) SELECT 'scope-'||i,'actor','a-'||i,'S',%s,7 FROM generate_series(1,%s) i",(TARGET,count))
        self.raw.execute('CREATE TEMP TABLE old_queue AS SELECT * FROM anomaly_detection.adp_scenario_jobs')
        old_updates=0
        for _ in range(repeats):
            old_updates+=self.raw.execute('UPDATE old_queue SET version=version+1,dirty=TRUE,due_ns=0 WHERE service_path=%s AND target_ns>=%s AND target_ns<=%s',('S',TARGET,TARGET+scenarios.HORIZON)).rowcount
            scenarios.changed_many(self.store,[('S',TARGET)])
        self.assertEqual(old_updates,count*repeats)
        self.assertEqual(self.store.scenario_queue_activity['batched_scope_change']['rows_affected'],0)
        row=self.raw.execute('SELECT COUNT(*) AS n,MIN(version) AS lo,MAX(version) AS hi,BOOL_AND(dirty) AS pending FROM anomaly_detection.adp_scenario_jobs').fetchone()
        self.assertEqual(dict(row),{'n':count,'lo':7,'hi':7,'pending':True})

    def test_completed_deferred_and_inflight_jobs_change_once_and_boundaries_hold(self):
        self.job('ready');self.job('done',dirty=False,processed_version=7)
        self.job('deferred',due_ns=999);self.job('running',claimed_version=7)
        self.job('before',target_ns=TARGET-1,dirty=False)
        self.job('edge',target_ns=TARGET+scenarios.HORIZON,dirty=False)
        self.job('after',target_ns=TARGET+scenarios.HORIZON+1,dirty=False)
        self.job('other',service_path='unrelated',dirty=False)
        for _ in range(20):scenarios.changed_many(self.store,[('S',TARGET)])
        for key in ('done','deferred','running','edge'):
            self.assertEqual(self.read(key)['version'],8);self.assertTrue(self.read(key)['dirty'])
            self.assertEqual(self.read(key)['due_ns'],0)
        for key in ('ready','before','after','other'):self.assertEqual(self.read(key)['version'],7)
        self.assertEqual(self.store.scenario_queue_activity['batched_scope_change']['rows_affected'],4)

    def test_concurrent_change_invalidates_claim_and_next_evaluation_consumes_latest(self):
        from psycopg.rows import dict_row
        self.job();self.population(1)
        with self.psycopg.connect(**self.params,dbname=self.name,autocommit=True,row_factory=dict_row) as other:
            other_store=ProductStore(other)
            def mutate():
                self.assertEqual(self.read()['claimed_version'],7)
                for _ in range(10):scenarios.changed_many(other_store,[('S',TARGET)])
                self.population(2)
            result=self.evaluate(mutate)
        self.assertEqual(result['status'],'INPUT_CHANGED_RETRY')
        self.assertTrue(self.read()['dirty']);self.assertEqual(self.read()['version'],8)
        self.assertEqual(self.read()['claimed_version'],0)
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_models').fetchone()['n'],0)
        result=self.evaluate()
        self.assertEqual(result['status'],'APPLIED')
        self.assertEqual(result['decisions'][0]['observed'],2)
        self.assertFalse(self.read()['dirty']);self.assertEqual(self.read()['processed_version'],8)

    def test_crash_after_claim_is_recoverable_by_the_single_writer(self):
        self.job(claimed_version=7);self.population(1)
        recovered=ProductStore(self.raw)
        self.store=recovered
        self.assertEqual(self.evaluate()['status'],'APPLIED')
        self.assertFalse(self.read()['dirty']);self.assertEqual(self.read()['claimed_version'],0)

    def test_replayed_enqueue_does_not_reopen_pending_jobs_but_completed_work_wakes(self):
        scenarios.enqueue(self.store,'actor','A','S',TARGET)
        key=scenarios.scope_key('actor','A','S',TARGET)
        for _ in range(30):scenarios.enqueue(self.store,'actor','A','S',TARGET)
        self.assertEqual(self.read(key)['version'],1)
        self.raw.execute('UPDATE anomaly_detection.adp_scenario_jobs SET dirty=FALSE,processed_version=version WHERE scope_key=%s',(key,))
        scenarios.enqueue(self.store,'actor','A','S',TARGET)
        self.assertEqual(self.read(key)['version'],2);self.assertTrue(self.read(key)['dirty'])

    def test_profile_task_replay_does_not_write_but_force_wakes_backoff(self):
        scenarios.queue_keys(self.store,['request'],priority=2,force=True)
        before=self.raw.execute('SELECT ctid::text AS tuple FROM anomaly_detection.adp_profile_tasks').fetchone()['tuple']
        for _ in range(20):scenarios.queue_keys(self.store,['request'],priority=2,force=True)
        self.assertEqual(self.raw.execute('SELECT ctid::text AS tuple FROM anomaly_detection.adp_profile_tasks').fetchone()['tuple'],before)
        self.raw.execute('UPDATE anomaly_detection.adp_profile_tasks SET due_ns=999')
        scenarios.queue_keys(self.store,['request'],priority=2,force=True)
        self.assertEqual(self.raw.execute('SELECT due_ns FROM anomaly_detection.adp_profile_tasks').fetchone()['due_ns'],0)

    def test_schema_upgrade_preserves_existing_queue_and_restart_skips_ddl(self):
        from anomaly_detection.schema_setup import ensure
        self.job(dirty=False,processed_version=7)
        self.raw.execute('DROP INDEX anomaly_detection.adp_scenario_invalidatable')
        self.raw.execute('ALTER TABLE anomaly_detection.adp_scenario_jobs DROP COLUMN claimed_version')
        self.raw.execute("SET statement_timeout='3s'")
        result=ensure(self.raw,scenarios.DDL)
        self.assertEqual(result['executed'],2)
        self.assertEqual(self.read()['claimed_version'],0)
        self.assertFalse(self.read()['dirty']);self.assertEqual(self.read()['version'],7)
        self.assertEqual(ensure(self.raw,scenarios.DDL)['executed'],0)
        self.assertEqual(self.raw.execute('SHOW statement_timeout').fetchone()['statement_timeout'],'3s')

    def test_new_global_generation_with_identical_membership_does_not_rewrite_or_requeue(self):
        from anomaly_detection.product_pipeline import apply_window
        self.assertEqual(apply_window(self.store,self.window_packet())['status'],'COMPLETE')
        self.raw.execute('UPDATE anomaly_detection.adp_scenario_jobs SET dirty=FALSE,processed_version=version')
        def members():return self.raw.execute('SELECT request_key,ctid::text AS tuple FROM anomaly_detection.adp_window_members ORDER BY request_key').fetchall()
        def jobs():return self.raw.execute('SELECT scope_key,version,dirty FROM anomaly_detection.adp_scenario_jobs ORDER BY scope_key').fetchall()
        def population():return self.raw.execute('SELECT start_ns,version,dirty FROM anomaly_detection.adp_population_jobs ORDER BY start_ns').fetchall()
        before=(members(),jobs(),population())
        self.assertEqual(apply_window(self.store,self.window_packet(2),cursor_name='overlap_cursor')['status'],'COMPLETE')
        self.assertEqual(before,(members(),jobs(),population()))
        self.assertEqual(self.raw.execute('SELECT stamp FROM anomaly_detection.adp_source_windows').fetchone()['stamp'],'stamp-2')
        self.assertEqual(apply_window(self.store,self.window_packet(3,2),cursor_name='overlap_cursor')['status'],'COMPLETE')
        self.assertNotEqual(before[0],members())
        self.assertTrue(any(r['dirty'] for r in jobs()))
        self.assertEqual(self.raw.execute('SELECT revision FROM anomaly_detection.adp_facts').fetchone()['revision'],2)

    def test_window_revision_failure_rolls_back_membership_fact_and_queue(self):
        from anomaly_detection.product_pipeline import apply_window
        apply_window(self.store,self.window_packet())
        before=self.raw.execute('SELECT stamp,source FROM anomaly_detection.adp_source_windows').fetchone()
        with patch('anomaly_detection.longitudinal.publish',side_effect=RuntimeError('injected publication failure')):
            with self.assertRaises(RuntimeError):apply_window(self.store,self.window_packet(2,2),cursor_name='overlap_cursor')
        self.assertEqual(self.raw.execute('SELECT stamp,source FROM anomaly_detection.adp_source_windows').fetchone(),before)
        self.assertEqual(self.raw.execute('SELECT revision FROM anomaly_detection.adp_facts').fetchone()['revision'],1)
        self.assertEqual(apply_window(self.store,self.window_packet(2,2),cursor_name='overlap_cursor')['status'],'COMPLETE')

    def test_unchanged_audit_does_not_dirty_population_again(self):
        from types import SimpleNamespace
        from anomaly_detection.product_pipeline import apply_window
        packet=self.window_packet();apply_window(self.store,packet);row=packet['rows'][0]
        fact={'request_key':row['request_key'],'semantic':row,'service_path':row['root_call'],
              'quality':{'identity_state':'assigned','conflicted':False,'evidence_available':True},
              'source_present':True,'observations':[]}
        audit=SimpleNamespace(source=packet['source'],keys=[row['request_key']],
            facts=lambda:[fact],requests={row['request_key']:{'session_key':row['session_key']}})
        self.assertEqual(self.store.apply_audit(audit)['evidence_changes'],1)
        before=self.raw.execute('SELECT version FROM anomaly_detection.adp_population_jobs').fetchone()['version']
        self.assertEqual(self.store.apply_audit(audit)['evidence_changes'],0)
        self.assertEqual(self.raw.execute('SELECT version FROM anomaly_detection.adp_population_jobs').fetchone()['version'],before)

    def test_longitudinal_seed_reuses_complete_summaries_without_fact_probes(self):
        from anomaly_detection.product_pipeline import apply_window
        from anomaly_detection.longitudinal import seed
        packet=self.window_packet();apply_window(self.store,packet)
        self.raw.execute('DELETE FROM anomaly_detection.adp_scenario_jobs')
        # Fact storage is deliberately unavailable to this seed: enumeration
        # is from the already qualified, complete actor/service summaries.
        self.raw.execute('ALTER TABLE anomaly_detection.adp_facts RENAME TO temporarily_unavailable_facts')
        seed(self.store,limit=8)
        rows=self.raw.execute('SELECT kind,entity_key,service_path,target_ns FROM anomaly_detection.adp_scenario_jobs').fetchall()
        self.assertEqual([dict(r) for r in rows],[{'kind':'longitudinal','entity_key':'b'*64,'service_path':'Services.v1/Fixture','target_ns':TARGET}])
        self.raw.execute('UPDATE anomaly_detection.adp_scenario_jobs SET dirty=FALSE,processed_version=version')
        # The independent old pass discovers the same scope once more. It
        # must not manufacture an input change for a completed job.
        self.store.save_state('longitudinal_seed_v2',{'turn':3})
        seed(self.store,limit=8)
        self.assertFalse(self.raw.execute('SELECT dirty FROM anomaly_detection.adp_scenario_jobs').fetchone()['dirty'])

    def test_summary_seed_advances_through_empty_parents_and_resumes_within_a_service_list(self):
        from anomaly_detection.product_pipeline import apply_window
        from anomaly_detection.longitudinal import seed
        packet=self.window_packet();apply_window(self.store,packet)
        self.raw.execute('DELETE FROM anomaly_detection.adp_scenario_jobs')
        empty=canonical({'coverage_complete':False,'counts':{}})
        self.raw.execute('INSERT INTO anomaly_detection.adp_windows SELECT lpad(n::text,64,\'0\'),%s,%s,%s FROM generate_series(1,130) n',
                         (TARGET,empty,'fixture-empty'))
        for _ in range(12):seed(self.store,limit=1)
        self.assertEqual(self.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_scenario_jobs').fetchone()['n'],1)
        state=self.store.state('longitudinal_seed_v2')
        self.assertLessEqual(state['last_parent_rows'],64)
        many=canonical({'coverage_complete':True,'population_complete':True,'counts':{'Services.v1/A':1,'Services.v1/B':2,'Services.v1/C':1}})
        self.raw.execute('DELETE FROM anomaly_detection.adp_scenario_jobs')
        self.raw.execute('DELETE FROM anomaly_detection.adp_windows')
        self.raw.execute('INSERT INTO anomaly_detection.adp_windows VALUES(%s,%s,%s,%s)',('d'*64,TARGET,many,'many'))
        self.store.save_state('longitudinal_seed_v2',{})
        for _ in range(12):seed(self.store,limit=1)
        services=[r['service_path'] for r in self.raw.execute('SELECT service_path FROM anomaly_detection.adp_scenario_jobs ORDER BY service_path').fetchall()]
        self.assertEqual(services,['Services.v1/A','Services.v1/B','Services.v1/C'])

    def test_viewer_disk_admission_observes_only_this_database_and_releases_without_source_locks(self):
        from anomaly_detection.viewer_priority import BUSY_SQL
        with self.psycopg.connect(**self.params,dbname=self.name,autocommit=True) as writer, \
             self.psycopg.connect(**self.params,dbname='postgres',autocommit=True) as other:
            self.assertFalse(self.raw.execute(BUSY_SQL).fetchone()['busy'])
            writer.execute('SELECT pg_advisory_lock(240026,2)')
            self.assertTrue(self.raw.execute(BUSY_SQL).fetchone()['busy'])
            writer.execute('SELECT pg_advisory_unlock(240026,2)')
            other.execute('SELECT pg_advisory_lock(240026,2)')
            self.assertFalse(self.raw.execute(BUSY_SQL).fetchone()['busy'])


if __name__=='__main__':unittest.main()
