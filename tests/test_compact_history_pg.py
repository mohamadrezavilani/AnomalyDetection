import concurrent.futures
from functools import lru_cache
import hashlib
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import types
import io
import tarfile
import tempfile
import json
import time
from urllib.request import urlopen
import unittest
from unittest.mock import Mock,patch
from compact_behavior import FIVE
from compact_behavior.extract import iso
from compact_behavior.store import Store
from compact_behavior.history import prepare,latest,finish
from compact_product.history import tick
from compact_ad import MODEL
from tests import test_compact_product_pg as fixture
from tests.test_compact_extract import row,extract,T
from tests.test_compact_operations import healthy_observation


@lru_cache(maxsize=1)
def installed_v5_store():
    root=Path(__file__).resolve().parents[1]
    code=subprocess.check_output(["git","show","018a75f817c1c141c03712b50f7477dd6d32e537:compact_behavior/store.py"],cwd=root)
    if hashlib.sha256(code).hexdigest()!="3db0eec10aec969cb0a85f08d59f51ba328499b726baedefa0fbd043e1182610":
        raise AssertionError("installed v5 Store bytes differ from the accepted release")
    module=types.ModuleType("compact_behavior._accepted_v5_store")
    module.__package__="compact_behavior"
    sys.modules[module.__name__]=module
    exec(compile(code,"accepted-v5-store.py","exec"),module.__dict__)
    return module.Store


def crash_history(database,schema,job_id,start,point):
    store=Store(database,schema=schema)
    store.publish("test",start,start+FIVE,extract([row("historical",at=iso(start+10**9))]),1,
        allow_history=True,history_job=job_id,fault=lambda where:os._exit(73) if where==point else None)
    os._exit(74)


@unittest.skipUnless(os.environ.get("P24_DELTA_PG_HOST"),"native PostgreSQL required")
class HistoryPostgresTests(unittest.TestCase):
    setUp=fixture.CompactProductPostgresTests.setUp
    tearDown=fixture.CompactProductPostgresTests.tearDown
    publish=fixture.CompactProductPostgresTests.publish
    analyze_at=fixture.CompactProductPostgresTests.analyze_at

    def test_launcher_drain_excludes_running_history_and_checks_job(self):
        from tools.Repair_Compact_History_Task import drain_with_lease
        from compact_product.runtime import role_key
        self.publish()
        expected=prepare(self.db,'test',T-2*FIVE)
        cursor=self.db.cursor('test')
        key=role_key(self.config,'test','history')
        other=Store(self.database,schema=self.config.source_schema)
        def acquire():
            return other.conn.execute('SELECT pg_try_advisory_lock(%s) AS ok',(key,)).fetchone()['ok']
        def unlock():
            other.conn.execute('SELECT pg_advisory_unlock(%s)',(key,))
        def while_draining():
            self.assertFalse(acquire())
            return {'status':'OWNED_LAUNCHER_STOP_REQUESTED'}
        def drain(job):
            return drain_with_lease(self.db,key,job,lambda:latest(self.db,'test'),while_draining)
        try:
            self.assertTrue(acquire())
            self.assertEqual(drain(expected)['status'],'WAITING_FOR_HISTORY_LEASE')
            unlock()
            with self.assertRaisesRegex(ValueError,'CHECKPOINT'):
                drain(dict(expected,job_id='different'))
            self.assertEqual(drain(expected)['status'],'OWNED_LAUNCHER_STOP_REQUESTED')
            self.assertTrue(acquire())
            unlock()
            self.assertEqual(latest(self.db,'test'),expected)
            self.assertEqual(self.db.cursor('test'),cursor)
        finally:
            other.close()

    def test_narrow_scope_is_atomic_preserves_live_and_fences_old_workers(self):
        from psycopg.errors import CheckViolation
        from compact_behavior.store import stream_lock
        from tools.Narrow_Compact_History import audit_for, narrow
        self.publish()
        old_floor, floor = T-20*FIVE, T-2*FIVE
        original = prepare(self.db, "test", old_floor)
        self.db.publish("test",old_floor,old_floor+FIVE,{},0,allow_history=True,history_job=original["job_id"])
        prior = latest(self.db, "test")
        deadline = (max(T,time.time_ns())//FIVE+288)*FIVE
        args = (self.db,"test",old_floor,floor,T,deadline)
        other = Store(self.database,schema=self.config.source_schema)
        try:
            with other.conn.transaction():
                other.conn.execute("SELECT pg_advisory_xact_lock(%s)",(stream_lock("test"),))
                with self.assertRaisesRegex(TimeoutError,"stream_busy"):
                    narrow(*args,wait_seconds=0)
        finally:
            other.close()
        with self.assertRaisesRegex(ValueError,"target_mismatch"):
            narrow(self.db,"test",old_floor,floor,T+FIVE,deadline)
        with self.assertRaisesRegex(ValueError,"passed_requested_start"):
            narrow(self.db,"test",old_floor,prior["next_ns"],T,deadline)
        self.assertEqual(latest(self.db,"test"),prior)
        schema=self.config.source_schema
        # A failure after the audit insert must leave neither a new job nor an audit.
        self.db.conn.execute(f"ALTER TABLE {schema}.history_jobs ADD CONSTRAINT test_block_rotation CHECK(from_ns={old_floor})")
        with self.assertRaises(CheckViolation):
            narrow(*args)
        self.assertIsNone(audit_for(self.db,prior["job_id"]))
        self.assertIsNone(self.db.conn.execute("SELECT to_regclass(%s) AS t",(schema+".history_scope_changes",)).fetchone()["t"])
        self.db.conn.execute(f"ALTER TABLE {schema}.history_jobs DROP CONSTRAINT test_block_rotation")
        self.assertEqual(narrow(*args),"APPLIED")
        job=latest(self.db,"test")
        self.assertNotEqual(job["job_id"],prior["job_id"])
        self.assertEqual(audit_for(self.db,job["job_id"])["previous_job"],prior)
        self.assertEqual((job["from_ns"],job["next_ns"],job["target_ns"],job["published_windows"]),(floor,floor,T,0))
        self.assertEqual(self.db.cursor("test"),T+FIVE)
        with self.assertRaisesRegex(ValueError,"not_authorized"):
            self.db.publish("test",prior["next_ns"],prior["next_ns"]+FIVE,{},0,allow_history=True,history_job=prior["job_id"])
        self.db.publish("test",floor,floor+FIVE,{},0,allow_history=True,history_job=job["job_id"])
        after=latest(self.db,"test")
        self.assertEqual(narrow(*args),"ALREADY_APPLIED")
        self.assertEqual(latest(self.db,"test"),after)
        self.assertEqual(self.db.cursor("test"),T+FIVE)
        self.assertEqual(self.db.conn.execute(f"SELECT count(*) AS n FROM {schema}.windows WHERE stream_id='test' AND start_ns<%s",(floor,)).fetchone()["n"],1)

    def test_narrowed_presentation_requires_contiguous_current_ad_and_live(self):
        from tools.Narrow_Compact_History import narrow, report
        self.publish()
        old_floor, floor = T-20*FIVE, T-2*FIVE
        prepare(self.db,"test",old_floor)
        narrow(self.db,"test",old_floor,floor,T,(max(T,time.time_ns())//FIVE+288)*FIVE)
        job=latest(self.db,"test")
        end=T+FIVE
        healthy=dict(roles={name:dict(running=True,heartbeat_age_seconds=1,state="RUNNING")
                          for name in ("ingest","analysis","web","supervisor")},
                     source_backlog_windows=0,reference_pending_windows=0,analysis_pending_windows=0)
        def snapshot(closed=end):
            with patch("tools.Narrow_Compact_History.time.time_ns",return_value=closed+self.config.source_lag_seconds*10**9), patch("tools.Narrow_Compact_History.health",return_value=healthy):
                return report(self.db,self.config,"test")
        self.assertEqual(snapshot()["history"]["missing_source"],2)
        for start in (floor,floor+FIVE):
            self.db.publish("test",start,start+FIVE,{},0,allow_history=True,history_job=job["job_id"])
        v=snapshot()
        self.assertEqual((v["history"]["missing_source"],v["history"]["published_awaiting_ad"]),(0,2))
        self.assertEqual(v["status"],"COMPACT_SCOPE_IN_PROGRESS")
        while self.db.step("test")["status"]!="ANALYSIS_IDLE": pass
        self.assertTrue(finish(self.db,"test",latest(self.db,"test"),self.config.ad_schema,MODEL))
        self.assertEqual(snapshot()["status"],"CONTIGUOUS_HISTORY_AND_LIVE_AD_CURRENT")
        # A missing live window or a now-stale base revision must revoke readiness.
        self.assertEqual(snapshot(end+FIVE)["live"]["missing_source"],1)
        self.assertEqual(snapshot(end+FIVE)["status"],"COMPACT_SCOPE_IN_PROGRESS")
        self.db.conn.execute(f"UPDATE {self.config.ad_schema}.window_results SET source_published_ns=0 WHERE stream_id='test' AND start_ns=%s",(floor,))
        v=snapshot()
        self.assertEqual(v["history"]["published_awaiting_ad"],1)
        self.assertEqual(v["status"],"COMPACT_SCOPE_IN_PROGRESS")

    def test_history_attachment_avoids_live_writer_ddl_lock_and_preserves_cursors(self):
        from compact_product.history_schema import validate_installed, existing_job
        from compact_product.runtime import Lease, runtime_init
        from psycopg.errors import LockNotAvailable
        self.publish()
        floor=T-400*FIVE
        runtime_init(self.db.conn,self.config.source_schema)
        job=prepare(self.db,"test",floor)
        blocker=Store(self.database,schema=self.config.source_schema)
        other=Store(self.database,schema=self.config.source_schema)
        try:
            with blocker.conn.transaction():
                # An ordinary live transaction holds RowExclusive until commit.
                blocker.conn.execute(f"UPDATE {self.config.source_schema}.streams SET next_ns=next_ns WHERE stream_id='test'")
                other.conn.execute("SET lock_timeout='100ms'")
                with self.assertRaises(LockNotAvailable): other.init()
                validate_installed(other,"test",history_required=True)
                self.assertEqual(existing_job(other,"test",floor),job)
                self.assertEqual(other.cursor("test"),T+FIVE)
                self.assertEqual(other.conn.execute('SHOW lock_timeout').fetchone()['lock_timeout'],'100ms')
                with tempfile.TemporaryDirectory() as directory, patch('compact_product.runtime.load',return_value=(self.config,{'DATABASE':self.database},'test')), patch.object(Store,'init',side_effect=AssertionError('unexpected source DDL')), patch('compact_product.runtime.runtime_init',side_effect=AssertionError('unexpected runtime DDL')):
                    supervisor = Lease(Path(directory), 'supervisor', 'installed-supervisor')
                    try:
                        self.assertEqual(supervisor.info['state'], 'STARTING')
                        with self.assertRaisesRegex(ValueError, 'ALREADY_RUNNING'):
                            Lease(Path(directory), 'supervisor', 'duplicate-supervisor')
                    finally:
                        supervisor.close()
                    lease=Lease(Path(directory),'history','read-only-attach-test')
                    try:
                        self.assertEqual(lease.info['state'],'STARTING')
                        with self.assertRaisesRegex(ValueError,'ALREADY_RUNNING'):
                            Lease(Path(directory),'history','duplicate')
                    finally: lease.close()
            self.assertEqual(latest(other,'test'),job)
            self.assertEqual(other.conn.execute('SHOW transaction_read_only').fetchone()['transaction_read_only'],'off')
            with self.assertRaisesRegex(ValueError,'compatible_compact_stream'):
                validate_installed(other,'different-stream',history_required=True)
            other.conn.execute(f'ALTER TABLE {self.config.source_schema}.pending_requests DROP COLUMN deadline_ns CASCADE')
            from psycopg.errors import UndefinedColumn
            with self.assertRaises(UndefinedColumn): validate_installed(other,'test',history_required=True)
        finally:
            blocker.close();other.close()

    def test_explicit_range_does_not_weaken_default_guard_or_rewind_live(self):
        self.publish(); floor=T-400*FIVE
        with self.assertRaisesRegex(ValueError,"24_hours"):
            self.db.publish("test",floor,floor+FIVE,{},0,allow_history=True)
        job=prepare(self.db,"test",floor)
        self.assertEqual((job["from_ns"],job["target_ns"],job["next_ns"]),(floor,T,floor))
        self.assertEqual(job["live_next_at_prepare_ns"],T+FIVE)
        self.db.publish("test",floor,floor+FIVE,{},0,allow_history=True,history_job=job["job_id"])
        self.assertEqual(self.db.cursor("test"),T+FIVE)
        self.assertEqual(latest(self.db,"test")["next_ns"],floor+FIVE)
        with self.assertRaisesRegex(ValueError,"not_authorized"):
            self.db.publish("test",floor,floor+FIVE,{},0,allow_history=True,history_job=job["job_id"])
        with self.assertRaisesRegex(ValueError,"24_hours"):
            self.db.publish("test",floor+FIVE,floor+2*FIVE,{},0,allow_history=True)
        self.assertEqual(prepare(self.db,"test",floor)["next_ns"],floor+FIVE)
        with self.assertRaisesRegex(ValueError,"another_history_range"):
            prepare(self.db,"test",floor-FIVE)

    def test_real_crash_before_and_after_commit_preserves_history_cursor(self):
        self.publish(); floor=T-400*FIVE; job=prepare(self.db,"test",floor)
        ctx=multiprocessing.get_context("spawn")
        for point in ("before_commit","after_commit"):
            child=ctx.Process(target=crash_history,args=(self.database,self.config.source_schema,job["job_id"],floor,point))
            child.start();child.join(25)
            self.assertEqual(child.exitcode,73)
            self.assertEqual(self.db.cursor("test"),T+FIVE)
            self.assertEqual(latest(self.db,"test")["next_ns"],floor+(FIVE if point=="after_commit" else 0))
        self.assertEqual(latest(self.db,"test")["published_windows"],1)

    def test_actual_accepted_v5_writer_and_history_publish_concurrently(self):
        self.publish(); floor=T-400*FIVE; job=prepare(self.db,"test",floor)
        def live():
            old=installed_v5_store()(self.database,schema=self.config.source_schema)
            try: return old.publish("test",T+FIVE,T+2*FIVE,extract([row("v5-live",at=iso(T+FIVE+10**9))]),1)
            finally:old.close()
        def historical():
            new=Store(self.database,schema=self.config.source_schema)
            try:return new.publish("test",floor,floor+FIVE,extract([row("historical",at=iso(floor+10**9))]),1,allow_history=True,history_job=job["job_id"])
            finally:new.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            values=list(pool.map(lambda f:f(),(live,historical)))
        self.assertTrue(all(v["fresh_publication"] for v in values))
        self.assertEqual(self.db.cursor("test"),T+2*FIVE)
        self.assertEqual(latest(self.db,"test")["next_ns"],floor+FIVE)
        while self.db.step("test")["status"]!="ANALYSIS_IDLE": pass
        self.assertEqual(self.db.conn.execute(f"SELECT count(*) AS n FROM {self.config.ad_schema}.window_results").fetchone()["n"],3)

    def test_source_completion_is_not_analysis_completion(self):
        self.publish(); floor=T-2*FIVE; job=prepare(self.db,"test",floor)
        for at in (floor,floor+FIVE):
            self.db.publish("test",at,at+FIVE,extract([row("history-"+str(at),at=iso(at+10**9))]),1,allow_history=True,history_job=job["job_id"])
        job=latest(self.db,"test")
        self.assertEqual(job["state"],"SOURCE_COMPLETE")
        self.assertFalse(finish(self.db,"test",job,self.config.ad_schema,MODEL))
        while self.db.step("test")["status"]!="ANALYSIS_IDLE": pass
        self.assertTrue(finish(self.db,"test",job,self.config.ad_schema,MODEL))
        self.assertEqual(latest(self.db,"test")["state"],"COMPLETE")

    def test_backpressure_does_not_fetch_or_publish_during_live_backlog(self):
        self.publish();self.analyze_at(T);floor=T-400*FIVE;job=prepare(self.db,"test",floor)
        ready=healthy_observation()["samples"][0]["health"]
        factory=Mock()
        with patch("compact_product.history.health",return_value=dict(ready,source_backlog_windows=1)):
            value=tick(self.db,self.config,{"ELASTICSEARCH":{}},"test",lambda:None,source_factory=factory)
        self.assertEqual(value["state"],"WAITING_FOR_LIVE_AND_ANALYSIS")
        factory.assert_not_called()
        self.assertEqual(latest(self.db,"test")["next_ns"],floor)

    def test_unconfirmed_ad_commit_is_requeued_not_falsely_acknowledged(self):
        self.publish(); floor=T-400*FIVE;prepare(self.db,"test",floor)
        def fail(point):
            if point=="after_commit":raise RuntimeError("artificial post-commit crash")
        with self.assertRaises(RuntimeError): self.db.step("test",fault=fail)
        value=tick(self.db,self.config,{"ELASTICSEARCH":{}},"test",lambda:None)
        self.assertEqual(value["state"],"WAITING_FOR_ANALYSIS_TIMING")
        timing=self.db.conn.execute(f"SELECT timing_confirmed_revision,revision FROM {self.config.ad_schema}.window_results").fetchone()
        self.assertNotEqual(timing["timing_confirmed_revision"],timing["revision"])
        self.db.step("test")
        timing=self.db.conn.execute(f"SELECT timing_confirmed_revision,revision FROM {self.config.ad_schema}.window_results").fetchone()
        self.assertEqual(timing["timing_confirmed_revision"],timing["revision"])

    def test_real_v5_requires_model_upgrade_then_history_continues_without_rewind(self):
        from compact_product.runtime import stop
        from compact_product import BUILD
        from compact_product.history import core_ready
        from compact_product.health import health
        from compact_behavior.source import ElasticWindow
        from tests.test_compact_product_runtime import elastic_server,free_port
        with tempfile.TemporaryDirectory() as directory, elastic_server() as url:
            root=Path(directory)/"data";root.mkdir()
            old=Path(directory)/"accepted-v5";old.mkdir()
            archive=subprocess.check_output(["git","archive","018a75f817c1c141c03712b50f7477dd6d32e537"],cwd=Path(__file__).resolve().parents[1])
            with tarfile.open(fileobj=io.BytesIO(archive)) as packed:packed.extractall(old,filter="data")
            ports=[free_port(),free_port()]
            elastic=dict(host=url,index_pattern="logs-*")
            (root/"viewer_config.local.py").write_text("DATABASE="+repr(self.database)+"\nELASTICSEARCH="+repr(elastic),encoding="utf-8")
            (root/"compact_product.local.json").write_text(json.dumps(dict(source_schema=self.config.source_schema,ad_schema=self.config.ad_schema,web_ports=ports,reference_windows=12,idle_seconds=1)),encoding="utf-8")
            stream=ElasticWindow(elastic,0,FIVE).namespace
            child=None
            try:
                launch=subprocess.run([sys.executable,"-B","-m","compact_product","start","--project",str(root)],cwd=old,capture_output=True,text=True,timeout=45)
                self.assertEqual(launch.returncode,0,launch.stdout+launch.stderr)
                deadline=time.monotonic()+60
                while time.monotonic()<deadline:
                    try:
                        with urlopen("http://127.0.0.1:"+str(ports[0])+"/api/status",timeout=2) as response:
                            h=json.load(response)
                        if core_ready(h):break
                    except OSError:
                        pass
                    time.sleep(.25)
                else:self.fail("accepted v5 roles did not become ready under their own model")
                self.assertTrue(all(h["roles"][r]["build"]=="COMPACT-PRODUCT-20261121-5" for r in ("ingest","analysis","web")))
                identities={r:h["roles"][r]["command_token"] for r in ("ingest","analysis","web","supervisor")}
                cursor=self.db.cursor(stream)
                first=self.db.conn.execute(f"SELECT min(start_ns) AS n FROM {self.config.source_schema}.windows WHERE stream_id=%s",(stream,)).fetchone()["n"]
                job=prepare(self.db,stream,first-3*FIVE)
                # The accepted v5 workers are healthy under MODEL 2. They must
                # not satisfy MODEL 3 readiness or let new history bypass AD.
                factory=Mock()
                value=tick(self.db,self.config,{"ELASTICSEARCH":elastic},stream,lambda:None,source_factory=factory)
                self.assertEqual(value["state"],"WAITING_FOR_LIVE_AND_ANALYSIS")
                factory.assert_not_called()
                self.assertEqual(latest(self.db,stream)["next_ns"],job["from_ns"])
                stop(root)
                launch=subprocess.run([sys.executable,"-B","-m","compact_product","start","--project",str(root)],cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,timeout=45)
                self.assertEqual(launch.returncode,0,launch.stdout+launch.stderr)
                deadline=time.monotonic()+60
                while time.monotonic()<deadline:
                    h=health(self.db.conn,self.config,stream)
                    if core_ready(h):break
                    time.sleep(.25)
                else:self.fail("new core did not migrate accepted v5 analysis")
                self.assertTrue(all(h["roles"][r]["build"]==BUILD for r in ("ingest","analysis","web","supervisor")))
                self.assertTrue(all(h["roles"][r]["command_token"]!=token for r,token in identities.items()))
                self.assertEqual(latest(self.db,stream)["job_id"],job["job_id"])
                self.assertEqual(latest(self.db,stream)["next_ns"],job["from_ns"])
                identities={r:h["roles"][r]["command_token"] for r in identities}
                child=subprocess.Popen([sys.executable,"-B","-m","compact_product","history-worker","--project",str(root)],cwd=Path(__file__).resolve().parents[1],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                deadline=time.monotonic()+60
                while time.monotonic()<deadline:
                    if latest(self.db,stream)["state"]=="COMPLETE":break
                    if child.poll() is not None:self.fail("history exited early: "+child.communicate()[0].decode())
                    time.sleep(.25)
                else:self.fail("history did not finish with acknowledged analysis")
                child.communicate(timeout=15)
                self.assertEqual(child.returncode,0)
                h=health(self.db.conn,self.config,stream)
                self.assertTrue(all(h["roles"][r]["command_token"]==token for r,token in identities.items()))
                self.assertGreaterEqual(self.db.cursor(stream),cursor)
                self.assertEqual(latest(self.db,stream)["published_windows"],3)
                with urlopen("http://127.0.0.1:"+str(ports[0])+"/healthz",timeout=5) as response:
                    self.assertEqual(json.load(response)["build"],BUILD)
            finally:
                if child is not None and child.poll() is None:
                    child.terminate();child.communicate(timeout=15)
                stop(root)


if __name__=="__main__":unittest.main()
