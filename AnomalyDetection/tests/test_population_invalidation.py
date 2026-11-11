"""Population publication must invalidate a scope once per atomic input change.

SQLite exercises stored state and rollback; its small SQL adapter below is not
a native PostgreSQL planner, concurrency or capacity qualification.
"""
from contextlib import contextmanager
import json
import sqlite3
import unittest
from unittest.mock import patch

from anomaly_detection import FIVE_NS
from anomaly_detection import population,scenario_store
from anomaly_detection.snapshot import canonical,digest

TARGET=100*FIVE_NS


class Cursor:
    def __init__(self,cursor):self.cursor=cursor
    @property
    def rowcount(self):return self.cursor.rowcount
    def fetchone(self):
        row=self.cursor.fetchone()
        return dict(row) if row is not None else None
    def fetchall(self):return [dict(row) for row in self.cursor.fetchall()]


class Database:
    def __init__(self):
        self.db=sqlite3.connect(':memory:',isolation_level=None)
        self.db.row_factory=sqlite3.Row
        self.db.execute("ATTACH DATABASE ':memory:' AS anomaly_detection")
        self.statements=[]
        self.db.executescript('''
          CREATE TABLE anomaly_detection.adp_population_jobs(start_ns INTEGER PRIMARY KEY,version INTEGER DEFAULT 1,processed_version INTEGER DEFAULT 0,dirty INTEGER DEFAULT 1,due_ns INTEGER DEFAULT 0);
          CREATE TABLE anomaly_detection.adp_source_windows(start_ns INTEGER PRIMARY KEY,source TEXT,complete INTEGER);
          CREATE TABLE anomaly_detection.adp_window_members(start_ns INTEGER,request_key TEXT,body TEXT);
          CREATE TABLE anomaly_detection.adp_facts(request_key TEXT PRIMARY KEY,details TEXT,revision INTEGER,anchor_key TEXT,source_present INTEGER,state TEXT);
          CREATE TABLE anomaly_detection.adp_population(service_path TEXT,start_ns INTEGER,body TEXT,content_digest TEXT,PRIMARY KEY(service_path,start_ns));
          CREATE TABLE anomaly_detection.adp_scenario_jobs(scope_key TEXT PRIMARY KEY,kind TEXT,entity_key TEXT,service_path TEXT,target_ns INTEGER,version INTEGER DEFAULT 1,processed_version INTEGER DEFAULT 0,dirty INTEGER DEFAULT 1,due_ns INTEGER DEFAULT 0,claimed_version INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE anomaly_detection.adp_case_signals(case_key TEXT,target_ns INTEGER,state TEXT,qualified INTEGER,review_eligible INTEGER,end_ns INTEGER);
          CREATE TABLE anomaly_detection.adp_case_feedback(case_key TEXT,id INTEGER,case_revision INTEGER,reviewed_end_ns INTEGER,label TEXT);
          CREATE TABLE anomaly_detection.adp_cases(case_key TEXT,revision INTEGER);
        ''')
    def execute(self,sql,args=()):
        self.statements.append((sql,args))
        if sql.startswith('UPDATE anomaly_detection.adp_scenario_jobs j SET') and 'jsonb_to_recordset' in sql:
            rows=json.loads(args[0])
            # Only expand the existing PostgreSQL recordset input. The real
            # UPDATE FROM and version/dirty values are applied by SQLite.
            incoming=' UNION ALL '.join('SELECT ? AS service,? AS first,? AS last' for _ in rows)
            sql=sql.replace('adp_scenario_jobs j SET version=version+1','adp_scenario_jobs AS j SET version=j.version+1')
            sql=sql.replace('jsonb_to_recordset(%s::jsonb) AS x(service TEXT,first BIGINT,last BIGINT)','('+incoming+') AS x')
            args=tuple(value for row in rows for value in (row['service'],row['first'],row['last']))
        sql=sql.replace('=ANY(%s)',' IN (SELECT value FROM json_each(%s))').replace('%s','?')
        args=tuple(json.dumps(a) if isinstance(a,list) else a for a in args)
        return Cursor(self.db.execute(sql,args))


class Store:
    def __init__(self):self.raw=Database()
    @contextmanager
    def transaction(self):
        self.raw.db.execute('BEGIN')
        try:
            yield
            self.raw.db.execute('COMMIT')
        except BaseException:
            self.raw.db.execute('ROLLBACK')
            raise


class PopulationInvalidationTests(unittest.TestCase):
    def setUp(self):
        self.store=Store();self.addCleanup(self.store.raw.db.close)
        self.services=['Services.v1/Fixture'+str(i) for i in range(100)]
        raw=self.store.raw
        raw.execute('INSERT INTO anomaly_detection.adp_population_jobs(start_ns) VALUES(%s)',(TARGET,))
        raw.execute('INSERT INTO anomaly_detection.adp_source_windows VALUES(%s,%s,TRUE)',(TARGET,canonical({'peer_population_valid':True})))
        for i,service in enumerate(self.services):
            self.member(service,i)
            key=scenario_store.scope_key('canonical_traffic',service,service,TARGET)
            raw.execute('INSERT INTO anomaly_detection.adp_scenario_jobs(scope_key,kind,entity_key,service_path,target_ns,version,processed_version,dirty,due_ns) VALUES(%s,%s,%s,%s,%s,7,7,FALSE,999)',(key,'canonical_traffic',service,service,TARGET))
        for key,service,at in [('shared','*',TARGET),('before','*',TARGET-1),('edge','*',TARGET+scenario_store.HORIZON),('after','*',TARGET+scenario_store.HORIZON+1),('unrelated','Services.v1/Other',TARGET)]:
            raw.execute('INSERT INTO anomaly_detection.adp_scenario_jobs(scope_key,kind,entity_key,service_path,target_ns,version,processed_version,dirty,due_ns) VALUES(%s,%s,%s,%s,%s,7,7,TRUE,999)',(key,'response','fixture',service,at))
        raw.statements.clear()
    def member(self,service,index):
        key=digest(['request',index]);anchor='ba1:'+key
        body={'kind':'service_execution','root_call':service,'session_key':'a'*64,'request_session_key':'a'*64,'identity_state':'assigned','conflicted':False,'revision':1}
        self.store.raw.execute('INSERT INTO anomaly_detection.adp_facts VALUES(%s,NULL,1,%s,TRUE,%s)',(key,anchor,'active'))
        self.store.raw.execute('INSERT INTO anomaly_detection.adp_window_members VALUES(%s,%s,%s)',(TARGET,key,canonical(body)))
    def run_population(self,*,fail=False):
        with patch('anomaly_detection.cases.replace_scope',side_effect=RuntimeError('rollback fixture') if fail else None),patch('anomaly_detection.cases.normal_observations'):
            return population.process_one(self.store,TARGET+FIVE_NS)
    def job(self,key):return self.store.raw.execute('SELECT * FROM anomaly_detection.adp_scenario_jobs WHERE scope_key=%s',(key,)).fetchone()
    def requeue(self):
        self.store.raw.execute('UPDATE anomaly_detection.adp_population_jobs SET dirty=TRUE,version=version+1 WHERE start_ns=%s',(TARGET,))

    def test_one_hundred_services_invalidate_shared_scope_once_in_one_statement(self):
        self.assertEqual(self.run_population()['status'],'APPLIED')
        self.assertEqual(self.job('shared')['version'],8)
        writes=[s for s,a in self.store.raw.statements if s.startswith('UPDATE anomaly_detection.adp_scenario_jobs')]
        self.assertEqual(len(writes),1)
        for service in self.services:
            job=self.job(scenario_store.scope_key('canonical_traffic',service,service,TARGET))
            self.assertEqual(job['version'],8)
            self.assertTrue(job['dirty'])

    def test_horizon_boundaries_and_unrelated_services_are_preserved(self):
        self.run_population()
        self.assertEqual(self.job('edge')['version'],8)
        for key in ('before','after','unrelated'):
            self.assertEqual(self.job(key)['version'],7)
        # A deferred dirty job must wake for its new input.
        self.assertTrue(self.job('shared')['dirty'])
        self.assertEqual(self.job('shared')['version'],8)

    def test_pending_updates_coalesce_but_an_inflight_read_is_invalidated_once(self):
        raw=self.store.raw
        raw.execute('UPDATE anomaly_detection.adp_scenario_jobs SET due_ns=0 WHERE scope_key=%s',('shared',))
        scenario_store.changed_many(self.store,[(self.services[0],TARGET)])
        self.assertEqual(self.job('shared')['version'],7)
        raw.execute('UPDATE anomaly_detection.adp_scenario_jobs SET claimed_version=version WHERE scope_key=%s',('shared',))
        scenario_store.changed_many(self.store,[(self.services[0],TARGET)])
        self.assertEqual(self.job('shared')['version'],8)
        scenario_store.changed_many(self.store,[(self.services[0],TARGET)])
        self.assertEqual(self.job('shared')['version'],8)
        self.assertEqual(self.job('shared')['claimed_version'],7)

    def test_profile_changes_do_not_invalidate_canonical_or_technical_traffic(self):
        raw=self.store.raw
        service=self.services[0]
        raw.execute("INSERT INTO anomaly_detection.adp_scenario_jobs(scope_key,kind,service_path,target_ns,dirty) VALUES('technical','traffic',%s,%s,FALSE)",(service,TARGET))
        canonical_key=scenario_store.scope_key('canonical_traffic',service,service,TARGET)
        scenario_store.changed(self.store,[service],TARGET,profile_only=True)
        self.assertEqual(self.job('technical')['version'],1)
        self.assertFalse(self.job('technical')['dirty'])
        self.assertEqual(self.job(canonical_key)['version'],7)
        self.assertFalse(self.job(canonical_key)['dirty'])

    def test_unchanged_publication_does_not_dirty_an_already_evaluated_scenario(self):
        self.run_population()
        self.store.raw.execute('UPDATE anomaly_detection.adp_scenario_jobs SET dirty=FALSE,processed_version=version')
        before={r['scope_key']:dict(r) for r in self.store.raw.execute('SELECT * FROM anomaly_detection.adp_scenario_jobs').fetchall()}
        self.requeue();self.store.raw.statements.clear();self.run_population()
        after={r['scope_key']:dict(r) for r in self.store.raw.execute('SELECT * FROM anomaly_detection.adp_scenario_jobs').fetchall()}
        self.assertEqual(before,after)
        self.assertFalse(any(s.startswith('UPDATE anomaly_detection.adp_scenario_jobs') for s,a in self.store.raw.statements))

    def test_unchanged_publication_still_creates_a_missing_canonical_scenario(self):
        self.run_population()
        key=scenario_store.scope_key('canonical_traffic',self.services[0],self.services[0],TARGET)
        self.store.raw.execute('DELETE FROM anomaly_detection.adp_scenario_jobs WHERE scope_key=%s',(key,))
        self.requeue();self.run_population()
        self.assertTrue(self.job(key)['dirty'])
        self.assertEqual(self.job(key)['version'],1)

    def test_one_changed_service_keeps_other_service_versions_and_bumps_shared_once(self):
        self.run_population()
        self.store.raw.execute('UPDATE anomaly_detection.adp_scenario_jobs SET dirty=FALSE,processed_version=version')
        before=self.job('shared')['version']
        self.member(self.services[0],1000);self.requeue();self.run_population()
        self.assertEqual(self.job('shared')['version'],before+1)
        self.assertTrue(self.job('shared')['dirty'])
        first=self.job(scenario_store.scope_key('canonical_traffic',self.services[0],self.services[0],TARGET))
        other=self.job(scenario_store.scope_key('canonical_traffic',self.services[1],self.services[1],TARGET))
        self.assertEqual(first['version'],9)
        self.assertEqual(other['version'],8)
        self.assertFalse(other['dirty'])

    def test_failed_case_publication_rolls_back_queue_versions_and_population(self):
        before={r['scope_key']:dict(r) for r in self.store.raw.execute('SELECT * FROM anomaly_detection.adp_scenario_jobs').fetchall()}
        with self.assertRaisesRegex(RuntimeError,'rollback fixture'):
            self.run_population(fail=True)
        after={r['scope_key']:dict(r) for r in self.store.raw.execute('SELECT * FROM anomaly_detection.adp_scenario_jobs').fetchall()}
        self.assertEqual(before,after)
        self.assertEqual(self.store.raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_population').fetchone()['n'],0)
        self.assertTrue(self.store.raw.execute('SELECT dirty FROM anomaly_detection.adp_population_jobs').fetchone()['dirty'])


if __name__=='__main__':unittest.main()
