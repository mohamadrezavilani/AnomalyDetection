"""C2 scoped body eligibility equals the original COUNT plus body read."""
from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
import unittest
import uuid

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_online import bind_stream,initialize_live,publish_capture
from viewer_performance.capacity.baseline import run,semantic_snapshot
from viewer_performance.capacity.fixtures import corpus,write,row,sql,START,FIVE
from viewer_performance.capacity.contract_fetch_once import ContractFetchOnceDB


class ContractChecks:
    @contextmanager
    def database(self,kind,root,keys):
        if getattr(self,'native',False):
            name='p24_design_capacity_'+uuid.uuid4().hex[:16]+'_qualification'
            self.admin.execute(self.pgsql.SQL('CREATE DATABASE {}').format(self.pgsql.Identifier(name)))
            options=dict(config={**self.parameters,'dbname':name,'options':'-c jit=off'},keys_path=keys)
        else:options=dict(sqlite_path=root/(uuid.uuid4().hex+'.db'),keys_path=keys)
        try:
            with kind(**options) as db:
                db.init();initialize_live(db);bind_stream(db,start_ns=START,stream_key='contract-once-tests')
                yield db
        finally:
            if getattr(self,'native',False):
                self.admin.execute(self.pgsql.SQL('DROP DATABASE {}').format(self.pgsql.Identifier(name)))

    def test_full_boundaries_include_conflict_withdrawal_and_late_payment(self):
        report=run(backend='postgresql' if getattr(self,'native',False) else 'sqlite',
            counts=(2,3,4),pairs=2,experiment='contract_fetch_once')
        self.assertEqual(report['status'],'PASS_CANDIDATE_EQUIVALENCE',report.get('failure'))
        self.assertTrue(report['candidate_exercised'])
        for lane in report['lanes']:
            if lane['variant']!='contract_fetch_once':continue
            stats=lane['candidate_report']['fetch_once']
            self.assertEqual(stats['scoped_calls'],4)
            self.assertGreater(stats['returned_bodies'],0)
            self.assertEqual(stats['missing_bodies'],0)
            self.assertGreater(lane['windows'][-1]['semantic_states'].get('withdrawn',0),0)

    def compare_missing(self,*,empty_first_batch=False,nonunique=False):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1))
            if empty_first_batch:
                events=[row(10_000+i,'one-operation-'+str(i),'DBPath.x.ud_prc_paymentExists',sql('K'+str(i)),START+FIVE) for i in range(401)]
                path=write(root/'large.gz',events,START+FIVE)
                jobs[1]=dict(path=path,start=START+FIVE,mode='forward')
            snapshots=[];candidate=None
            for kind in (ViewerDB,ContractFetchOnceDB):
                with self.database(kind,root,keys) as db:
                    first=jobs[0]
                    publish_capture(db,first['path'],first['start'],first['start']+FIVE)
                    if kind is ContractFetchOnceDB:db.prepare_candidate()
                    def remove(stage):
                        if stage!='after_requests':return
                        rows=db.all('SELECT origin_key,version_key FROM viewer_projection_events WHERE callpath LIKE ? ORDER BY origin_key,version_key',('%ud_prc_paymentExists%',))
                        selected=rows[:400] if empty_first_batch else rows[:1]
                        if nonunique:
                            db.sql('DROP INDEX public.vre_binary_origin_v1')
                            item=selected[0]
                            db.sql('INSERT INTO viewer_raw_events SELECT * FROM viewer_raw_events WHERE origin_key=? AND version_key=?',(item['origin_key'],item['version_key']))
                        else:
                            for item in selected:
                                db.sql('DELETE FROM viewer_raw_events WHERE origin_key=? AND version_key=?',(item['origin_key'],item['version_key']))
                    job=jobs[1]
                    publish_capture(db,job['path'],job['start'],job['start']+FIVE,fault=remove)
                    snapshots.append(semantic_snapshot(db))
                    if kind is ContractFetchOnceDB:candidate=db.candidate_report()['fetch_once']
            self.assertEqual(*snapshots)
            self.assertGreater(candidate['nonunique_bodies'] if nonunique else candidate['missing_bodies'],0)
            if empty_first_batch:
                self.assertGreater(candidate['returned_bodies'],0)
                self.assertGreater(candidate['body_pair_lookups'],400)

    def test_missing_raw_body_is_still_excluded(self):self.compare_missing()

    def test_empty_body_batch_does_not_hide_later_valid_rows(self):self.compare_missing(empty_first_batch=True)


class SQLiteContractFetchTests(ContractChecks,unittest.TestCase):pass


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'isolated PG18 not configured')
class NativeContractFetchTests(ContractChecks,unittest.TestCase):
    native=True

    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        cls.pgsql=sql
        cls.parameters=dict(host=os.environ['P24_DELTA_PG_HOST'],
            port=int(os.environ.get('P24_DELTA_PG_PORT','5432')),
            user=os.environ.get('P24_DELTA_PG_USER','postgres'),connect_timeout=3)
        cls.admin=psycopg.connect(**cls.parameters,dbname='postgres',autocommit=True)

    @classmethod
    def tearDownClass(cls):cls.admin.close()

    def test_unsupported_duplicate_bodies_remain_ineligible_as_in_original_count(self):
        self.compare_missing(nonunique=True)


if __name__=='__main__':unittest.main()
