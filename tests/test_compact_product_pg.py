from dataclasses import replace
import concurrent.futures
import contextlib
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import time
import unittest
import uuid
from compact_behavior import FIVE
from compact_behavior.store import Store, ALL
from compact_behavior.extract import iso, digest
from compact_ad.store import AnalysisStore, ChangedDuringAnalysis
from compact_ad.engine import evaluate
from compact_product.config import Config
from compact_product.runtime import runtime_init, Lease, status, stop
from compact_product.web import create_app
from tests.test_compact_extract import row, extract, T


def crash_analysis(config, schema, ad_schema, start, point):
    db = AnalysisStore(config, schema=schema, ad_schema=ad_schema)
    work = db.snapshot("test", start)
    results = evaluate(
        start, work["summary"], work["services"], work["actors"], work["references"]
    )
    db.commit_analysis(
        work,
        results,
        0.01,
        fault=lambda where: os._exit(73) if where == point else None,
    )
    os._exit(74)


@unittest.skipUnless(os.environ.get("P24_DELTA_PG_HOST"), "native PostgreSQL required")
class CompactProductPostgresTests(unittest.TestCase):
    def setUp(self):
        self.database = dict(
            host=os.environ["P24_DELTA_PG_HOST"],
            port=os.environ["P24_DELTA_PG_PORT"],
            user=os.environ["P24_DELTA_PG_USER"],
            dbname="postgres",
        )
        key = uuid.uuid4().hex[:10]
        self.config = Config(
            source_schema="p24_compact_p_" + key, ad_schema="p24_compact_ad_p_" + key
        )
        self.db = AnalysisStore(
            self.database,
            schema=self.config.source_schema,
            ad_schema=self.config.ad_schema,
        )
        self.db.init()

    def tearDown(self):
        self.db.conn.execute("DROP SCHEMA " + self.config.ad_schema + " CASCADE")
        self.db.conn.execute("DROP SCHEMA " + self.config.source_schema + " CASCADE")
        self.db.close()

    def test_independent_root_completes_pending_with_metadata_and_replay_is_idempotent(self):
        schema=self.config.source_schema
        pending=dict(row('partner-user',path='DBPath.pishkhan24.application.ud_prc_userSessionHasAccess',
            message='(SQL Parameters: @userAgent=PartnerBrowser @action=EwanoLogin)'),IP='192.0.2.7')
        self.db.publish('test',T,T+FIVE,extract([pending]),1)
        self.assertEqual(self.count('pending_requests',True),1)
        late=extract([row('partner-user',path='Ewano.v1/EwanoLogin',at=iso(T+FIVE+10**9))])
        self.db.publish('test',T+FIVE,T+2*FIVE,late,1)
        self.assertEqual(self.count('pending_requests',True),0)
        body=self.db.conn.execute(f'SELECT * FROM {schema}.behaviors').fetchone()
        self.assertEqual(body['api'],'Ewano.v1/EwanoLogin')
        context=self.db.conn.execute(f'SELECT * FROM {schema}.request_context').fetchone()
        self.assertIn('192.0.2.7',json.dumps(context,default=str))
        self.db.publish('test',T+FIVE,T+2*FIVE,late,1)
        self.assertEqual(self.count('behaviors',True),1)
        self.assertEqual(body,self.db.conn.execute(f'SELECT * FROM {schema}.behaviors').fetchone())
        counts=self.db.conn.execute(f'SELECT active_pending FROM {schema}.queue_counts').fetchone()
        self.assertEqual(counts['active_pending'],0)

    def test_topup_republication_updates_old_unknown_features_without_duplicate(self):
        from unittest.mock import patch
        from compact_behavior.services import operation_catalog
        schema=self.config.source_schema
        states=extract([row('topup',path='Services.v1/InvoiceRegister'),
            row('topup',path='DBPath.pishkhan24.application.ud_prc_userSessionHasAccess',message='(SQL Parameters: @action=v1/TopUpProductReserve)'),
            row('topup',path='DBPath.pishkhan24.application.ud_prc_invoiceRequest',message='(SQL Parameters: @serviceID=1202)')])
        with patch.dict(operation_catalog()['routes']['Services.v1/TopUpProductReserve'],role='unknown'):
            self.db.publish('test',T,T+FIVE,states,3)
        before=self.db.conn.execute(f'SELECT * FROM {schema}.behaviors').fetchone()
        self.assertFalse(before['features']['service_rate_eligible'])
        self.db.publish('test',T,T+FIVE,states,3)
        after=self.db.conn.execute(f'SELECT * FROM {schema}.behaviors').fetchone()
        self.assertEqual(before['behavior_id'],after['behavior_id'])
        self.assertEqual(after['revision'],before['revision']+1)
        self.assertTrue(after['features']['service_rate_eligible'])
        self.assertEqual(self.count('behaviors',True),1)
        self.db.publish('test',T,T+FIVE,states,3)
        self.assertEqual(after,self.db.conn.execute(f'SELECT * FROM {schema}.behaviors').fetchone())

    def test_unknown_review_separates_pending_and_roles_without_payload_export(self):
        from tools.Review_Compact_Unknowns import collect
        partial=lambda key,at:dict(row(key,path='ClientAyanCoInquiry.WaterBillInquiry',
            message='Input:{"BillID":"DoNotExportPayload"}',at=iso(at)),IP='192.0.2.123',UserAgent='DoNotExportAgent')
        self.db.publish('test',T,T+FIVE,extract([partial('triage-expired',T+10**9)]),1)
        for i in range(1,7):self.db.publish('test',T+i*FIVE,T+(i+1)*FIVE,{},0)
        self.db.publish('test',T+7*FIVE,T+8*FIVE,extract([
            partial('triage-pending',T+7*FIVE+10**9),
            row('triage-unknown',path='Services.v1/InvoiceRegister',at=iso(T+7*FIVE+10**9))]),2)
        before=self.db.conn.execute(f'SELECT * FROM {self.config.source_schema}.queue_counts').fetchall()
        with self.db.conn.transaction():
            self.db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            report=collect(self.db.conn,self.config.source_schema,'test',limit=2,scan=10)
        for group in ('WAITING','EXPIRED','UNKNOWN_BEHAVIORS'):
            self.assertEqual(report['groups'][group]['sampled_requests'],1)
        unknown=report['groups']['UNKNOWN_BEHAVIORS']['samples'][0]
        self.assertEqual(unknown['api'],'Services.v1/InvoiceRegister')
        self.assertIn('unresolved_dispatch',unknown['quality'])
        text=json.dumps(report)
        for private in ('DoNotExportPayload','192.0.2.123','DoNotExportAgent'):
            self.assertNotIn(private,text)
        self.assertIn('triage-pending',text)
        self.assertEqual(before,self.db.conn.execute(f'SELECT * FROM {self.config.source_schema}.queue_counts').fetchall())
        with self.assertRaises(ValueError):collect(self.db.conn,self.config.source_schema,'test',limit=101)

    def test_source_sample_reconciliation_tracks_cross_window_completion_read_only(self):
        from tools.Reconcile_Compact_Samples import collect
        keys=['1'*32,'2'*32,'3'*32,'4'*32]
        self.db.publish('test',T,T+FIVE,extract([
            row(keys[0],path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:{"BillID":"DoNotExportTarget"}'),
            row(keys[1],path='DBPath.pishkhan24.application.ud_prc_filesInfo',message='metadata'),
            row(keys[2],path='Services.v1/InvoiceRegister',message='POST https://example.test/InvoiceRegister HTTP/1.1 (GR0004 | RequestRateLimiting)'),
            row(keys[2],path='DBPath.pishkhan24.application.ud_prc_userSessionHasAccess',message='(SQL Parameters: @action=v1/LandLinePhoneBills)')]),4)
        original=dict(status='READ_ONLY_UNKNOWN_REVIEW',counters={'stream_id':'test'},groups={'sample':{'samples':[
            dict(request_id=k,first_observed_ns=T+10**9,last_observed_ns=T+10**9) for k in keys]}})
        evidence=dict(status='READ_ONLY_SOURCE_EVIDENCE',samples=[dict(request_id=k,review_group='WAITING',
            coverage='COMPLETE_WITHIN_QUERY_RANGE',recognized_apis=['Services.v1/WaterBills'],documents=[
                dict(http_completion=True,timestamp=iso(T+FIVE+10**9),call_path='Services.v1/WaterBills',logged_result_code='G00000')]) for k in keys[:2]]+
            [dict(request_id=k,review_group='UNKNOWN_BEHAVIORS',coverage='COMPLETE_WITHIN_QUERY_RANGE',documents=[]) for k in keys[2:]])
        def inspect():
            before=self.db.conn.execute(f'SELECT * FROM {self.config.source_schema}.queue_counts').fetchall()
            with self.db.conn.transaction():
                self.db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                r=collect(self.db.conn,self.config.source_schema,self.config.ad_schema,'test',original,evidence)
            self.assertEqual(before,self.db.conn.execute(f'SELECT * FROM {self.config.source_schema}.queue_counts').fetchall())
            self.assertNotIn('DoNotExportTarget',json.dumps(r,default=str))
            self.assertNotIn('session-1',json.dumps(r,default=str))
            return r
        before=inspect()
        self.assertEqual(before['locations'],{'WAITING':2,'BEHAVIOR':1,'NOT_FOUND':1})
        self.assertEqual(before['unpublished_window_starts_ns'],[T+FIVE])
        self.db.publish('test',T+FIVE,T+2*FIVE,extract([
            row(keys[0],at=iso(T+FIVE+10**9)),row(keys[1],path='Files.Download',at=iso(T+FIVE+10**9))]),2)
        after=inspect()
        self.assertEqual(after['locations'],{'BEHAVIOR':3,'NOT_FOUND':1})
        self.assertEqual(after['unpublished_window_starts_ns'],[])
        self.assertEqual(after['samples'][1]['behavior']['current_rule_role'],'support')
        rejected=after['samples'][2]['behavior']
        self.assertEqual(rejected['result_code'],'GR0004')
        self.assertEqual(rejected['current_rule_role'],'unknown')
        self.assertFalse(rejected['service_rate_eligible'])
        self.assertTrue(all(w['analysis_revision'] is None for w in after['windows']))

    def test_pending_diagnostic_is_read_only_and_excludes_request_values(self):
        from tools.Review_Compact_Pending import collect
        schema=self.config.source_schema
        runtime_init(self.db.conn,schema)
        self.db.publish('test',T,T+FIVE,extract([row('private-request',
            path='ClientAyanCoInquiry.WaterBillInquiry',message='Input:{"BillID":"private-target"}')]),1)
        before=self.db.conn.execute(f'SELECT * FROM {schema}.queue_counts').fetchall()
        with self.db.conn.transaction():
            self.db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            report=collect(self.db.conn,schema,'test',T+FIVE)
        self.assertEqual(report['due']['waiting'],1)
        self.assertEqual(report['due']['due_at_next_window_end'],0)
        self.assertEqual(report['waiting_deadline_buckets'][0]['requests'],1)
        self.assertEqual(report['stream']['next_ns'],T+FIVE)
        self.assertNotIn('private-request',json.dumps(report));self.assertNotIn('private-target',json.dumps(report))
        self.assertEqual(before,self.db.conn.execute(f'SELECT * FROM {schema}.queue_counts').fetchall())

    def test_collected_context_is_displayed_and_review_exports_only_counts(self):
        from tools.Review_Compact_Request_Metadata import sample
        self.db.publish('test', T, T + FIVE, extract([dict(row(request='context-request'),IP='192.0.2.1',UserAgent='Synthetic Browser')]), 1)
        bid=self.db.conn.execute(f"SELECT behavior_id FROM {self.config.source_schema}.behaviors LIMIT 1").fetchone()['behavior_id']
        client=create_app(self.config,self.database,'test',secret='test').test_client()
        response=client.get('/behaviors/'+bid)
        self.assertEqual(response.status_code,200)
        html=response.get_data(as_text=True)
        self.assertIn('192.0.2.1',html);self.assertIn('Synthetic Browser',html)
        self.assertIn('log.IP',html);self.assertIn('نخستین شاهد زمان‌دار',html)
        with self.db.conn.transaction():
            self.db.conn.execute('SET TRANSACTION READ ONLY')
            result=sample(self.db.conn,self.config.source_schema,'test')
        self.assertEqual(result['with_ip'],1);self.assertEqual(result['with_user_agent'],1)
        self.assertNotIn('192.0.2.1',json.dumps(result));self.assertNotIn('Synthetic Browser',json.dumps(result))

    def test_catalog_import_is_atomic_idempotent_and_readable_without_writes(self):
        from compact_product.error_catalog import CATALOG_VERSION, CATALOG_ROW_COUNT, definitions
        s = self.config.source_schema
        # A failed startup leaves no partial import/receipt.
        with self.assertRaisesRegex(RuntimeError, "rollback"):
            with self.db.conn.transaction():
                runtime_init(self.db.conn, s)
                raise RuntimeError("rollback")
        self.assertIsNone(self.db.conn.execute("SELECT to_regclass(%s) AS name", (s + ".error_catalog_imports",)).fetchone()["name"])
        runtime_init(self.db.conn, s)
        before = self.db.conn.execute(f"SELECT * FROM {s}.error_catalog_imports").fetchall()
        self.assertEqual(before[0]["row_count"], CATALOG_ROW_COUNT)
        # A subsequent process startup must not COPY or update the receipt.
        from unittest.mock import patch
        with patch("compact_product.error_catalog.catalog_records", side_effect=AssertionError("reimport")):
            runtime_init(self.db.conn, s)
        self.assertEqual(self.db.conn.execute(f"SELECT * FROM {s}.error_catalog_imports").fetchall(), before)
        self.assertEqual(self.db.conn.execute(f"SELECT count(*) AS n FROM {s}.error_code_definitions").fetchone()["n"], CATALOG_ROW_COUNT)
        with self.db.conn.transaction():
            self.db.conn.execute("SET TRANSACTION READ ONLY")
            r = definitions(self.db.conn, s, ['GR0010', 'GD2148', 'G00000', 'not-a-code'])
        self.assertEqual(r['GR0010'][0]['log_symbol'], 'ServiceUnavailable')
        self.assertEqual(r['GR0010'][0]['source']['row'], 11)
        self.assertIn('یکطرفه', r['GD2148'][0]['message_fa'])
        self.assertEqual(r['G00000'][0]['message_fa'], 'موفقیت سرویس')
        self.assertEqual(r['G00000'][0]['source']['kind'], 'owner_definition')
        self.assertNotIn('not-a-code', r)
        self.assertEqual(before[0]['version'], CATALOG_VERSION)
        # Older catalog receipts/definitions are not replaced during startup.
        self.db.conn.execute(f"INSERT INTO {s}.error_catalog_imports(version,row_count) VALUES('old-version',1)")
        self.db.conn.execute(f"INSERT INTO {s}.error_code_definitions SELECT 'old-version',entry_id,code,code_system,message_fa,log_symbol,definition_state,source FROM {s}.error_code_definitions WHERE version=%s AND code='GR0010'", (CATALOG_VERSION,))
        runtime_init(self.db.conn, s)
        self.assertEqual(self.db.conn.execute(f"SELECT count(*) AS n FROM {s}.error_code_definitions WHERE version='old-version'").fetchone()['n'], 1)

    def publish(self, start=T, n=10, **kw):
        records = []
        for i in range(n):
            key = "r" + str(start) + "-" + str(i)
            records.extend(
                [
                    row(key, "s" + str(i // 2), at=iso(start + 10**9)),
                    row(
                        key,
                        "s" + str(i // 2),
                        message='Input:{"BillID":"'
                        + str(i)
                        + '"} Output:{"Amount":10}',
                        at=iso(start + 10**9),
                    ),
                ]
            )
        return self.db.publish(
            "test", start, start + FIVE, extract(records), len(records), **kw
        )

    def analyze_at(self, start):
        work = self.db.snapshot("test", start)
        results = evaluate(
            start, work["summary"], work["services"], work["actors"], work["references"]
        )
        return self.db.commit_analysis(work, results, 0.01)

    def test_incident_publication_hides_dirty_unconfirmed_and_rejected_revision(self):
        self.publish()
        work = self.db.snapshot("test", T)
        results = evaluate(T, work["summary"], work["services"], work["actors"], [])
        results[0]["status"] = "ANOMALY"  # controlled display fixture, not accuracy evidence
        self.db.commit_analysis(work, results, .01)
        client = create_app(self.config, self.database, "test", secret="test").test_client()
        a, s = self.config.ad_schema, self.config.source_schema
        def visible():
            response = client.get("/incidents")
            self.assertEqual(response.status_code, 200)
            return "incident-groups/" in response.get_data(as_text=True)
        self.assertTrue(visible())
        row = self.db.conn.execute(f"SELECT finding_id,revision FROM {a}.findings WHERE status='ANOMALY'").fetchone()
        self.db.conn.execute(f"UPDATE {a}.window_results SET timing_confirmed_revision=0")
        self.assertFalse(visible())
        self.db.conn.execute(f"UPDATE {a}.window_results SET timing_confirmed_revision=revision")
        self.db.conn.execute(f"UPDATE {s}.dirty_windows SET version=version+1 WHERE session_id='@all'")
        self.assertFalse(visible())
        self.db.conn.execute(f"UPDATE {s}.dirty_windows SET processed_version=version")
        self.assertTrue(visible())
        self.db.conn.execute(f"INSERT INTO {a}.feedback(finding_id,finding_revision,verdict,note,recorded_at_ns) VALUES(%s,%s,'FALSE_POSITIVE','test',1)", (row['finding_id'],row['revision']))
        self.assertFalse(visible())
        self.assertEqual(client.get("/status").status_code, 200)

    def count(self, table, source=False):
        return self.db.conn.execute(
            "SELECT count(*) AS n FROM "
            + (self.config.source_schema if source else self.config.ad_schema)
            + "."
            + table
        ).fetchone()["n"]

    def test_dirty_exact_version_results_ack_and_queue_counter_atomic(self):
        self.publish()
        work = self.db.snapshot("test", T)
        late = extract([row("r" + str(T) + "-0", message="Output:[broken")])
        self.db.publish("test", T, T + FIVE, late, 1)
        results = evaluate(T, work["summary"], work["services"], work["actors"], [])
        with self.assertRaises(ChangedDuringAnalysis):
            self.db.commit_analysis(work, results, 0.01)
        self.assertEqual(self.count("window_results"), 0)
        self.assertGreater(
            self.db.conn.execute(
                "SELECT dirty_keys FROM " + self.config.source_schema + ".queue_counts"
            ).fetchone()["dirty_keys"],
            0,
        )
        self.analyze_at(T)
        self.assertEqual(
            self.db.conn.execute(
                "SELECT dirty_keys FROM " + self.config.source_schema + ".queue_counts"
            ).fetchone()["dirty_keys"],
            0,
        )

    def test_reference_change_during_first_target_analysis_is_fenced(self):
        self.publish(T)
        self.publish(T + FIVE)
        work = self.db.snapshot("test", T + FIVE)
        self.analyze_at(T)
        results = evaluate(
            T + FIVE,
            work["summary"],
            work["services"],
            work["actors"],
            work["references"],
        )
        with self.assertRaises(ChangedDuringAnalysis):
            self.db.commit_analysis(work, results, 0.01)
        self.assertEqual(self.count("window_results"), 1)
        self.analyze_at(T + FIVE)
        self.assertEqual(self.count("window_results"), 2)

    def test_second_expiry_preserves_counter_and_marks_lost_fragments(self):
        schema = self.config.source_schema
        for wave in range(2):
            begin = T + wave * 9 * FIVE
            records = extract(
                [
                    row(
                        "pending",
                        path="ClientAyanCoInquiry.WaterBillInquiry",
                        message='Input:{"BillID":"' + str(wave) + '"}',
                        at=iso(begin + 10**9),
                    )
                ]
            )
            self.db.publish("test", begin, begin + FIVE, records, 1)
            for i in range(1, 8):
                self.db.publish("test", begin + i * FIVE, begin + (i + 1) * FIVE, {}, 0)
            self.db.conn.execute(
                "UPDATE " + schema + ".pending_requests SET updated_at_ns=0"
            )
            self.db.publish("test", begin + 8 * FIVE, begin + 9 * FIVE, {}, 0)
            counts = self.db.conn.execute(
                "SELECT active_pending,expired_pending FROM " + schema + ".queue_counts"
            ).fetchone()
            self.assertEqual(
                (counts["active_pending"], counts["expired_pending"]), (0, 0)
            )
            self.assertEqual(self.count("pending_requests", True), 0)
            self.assertEqual(self.count("expired_fragments", True), 1)
        self.db.publish(
            "test",
            T + 18 * FIVE,
            T + 19 * FIVE,
            extract([row("pending", at=iso(T + 18 * FIVE + 10**9))]),
            1,
        )
        core = self.db.conn.execute("SELECT * FROM " + schema + ".behaviors").fetchone()
        self.assertIn("prior_fragments_expired", core["quality"])
        self.assertFalse(core["features"]["input_eligible"])

    def test_actual_analysis_crash_before_and_after_commit(self):
        self.publish()
        ctx = multiprocessing.get_context("spawn")
        for point in ("before_commit", "after_commit"):
            p = ctx.Process(
                target=crash_analysis,
                args=(
                    self.database,
                    self.config.source_schema,
                    self.config.ad_schema,
                    T,
                    point,
                ),
            )
            p.start()
            p.join(20)
            self.assertEqual(p.exitcode, 73)
            self.assertEqual(self.count("window_results"), int(point == "after_commit"))
        self.assertEqual(self.db.step("test")["status"], "ANALYSIS_IDLE")
        row = self.db.conn.execute(
            "SELECT first_analyzed_ns FROM " + self.config.ad_schema + ".window_results"
        ).fetchone()
        self.assertEqual(
            row["first_analyzed_ns"], 0
        )  # semantic commit survived; timing has no postcommit confirmation

    def test_later_analysis_crash_cannot_reuse_an_older_confirmed_timing(self):
        from compact_product.health import health
        self.publish()
        self.analyze_at(T)
        self.db.publish("test", T, T + FIVE, extract([row("r" + str(T) + "-0", message="Output:[broken")]), 1)
        work = self.db.snapshot("test", T)
        results = evaluate(T, work["summary"], work["services"], work["actors"], work["references"])
        def fail(point):
            if point == "after_commit":
                raise RuntimeError("crashed_before_revision_timing_confirmation")
        with self.assertRaises(RuntimeError):
            self.db.commit_analysis(work, results, .01, fault=fail)
        saved = self.db.conn.execute(f"SELECT * FROM {self.config.ad_schema}.window_results").fetchone()
        self.assertGreater(saved["first_analyzed_ns"], 0)
        self.assertLess(saved["timing_confirmed_revision"], saved["revision"])
        state = health(self.db.conn, self.config, "test")
        self.assertEqual(state["analysis_timing_unconfirmed_windows"], 1)
        self.assertFalse(state["latest_analysis_timing_confirmed"])
        self.assertEqual(state["analysis_latency_samples"], 0)

    def test_pending_reanalysis_is_not_reported_as_current_analysis(self):
        from compact_product.health import health
        self.publish()
        self.analyze_at(T)
        state = health(self.db.conn, self.config, "test")
        self.assertEqual(state["latest_analyzed_end_ns"], T + FIVE)
        self.db.conn.execute(f"INSERT INTO {self.config.ad_schema}.reanalysis(stream_id,start_ns,updated_at_ns) VALUES(%s,%s,%s)", ("test", T, time.time_ns()))
        state = health(self.db.conn, self.config, "test")
        self.assertIsNone(state["latest_analyzed_end_ns"])
        self.assertEqual(state["analysis_pending_windows"], 1)
        self.assertEqual(state["oldest_dirty_start_ns"], T)
        self.db.step("test")
        state = health(self.db.conn, self.config, "test")
        self.assertEqual(state["analysis_pending_windows"], 0)
        self.assertEqual(state["latest_analyzed_end_ns"], T + FIVE)
        self.assertTrue(state["latest_analysis_timing_confirmed"])

    def test_timing_confirmation_follows_semantic_commit_for_each_revision(self):
        self.publish()
        work = self.db.snapshot("test", T)
        results = evaluate(T, work["summary"], work["services"], work["actors"], [])
        after = []
        def pause(point):
            if point == "after_commit":
                time.sleep(.05)
                after.append(time.time_ns())
        self.db.commit_analysis(work, results, .01, fault=pause)
        saved = self.db.conn.execute(f"SELECT * FROM {self.config.ad_schema}.window_results").fetchone()
        self.assertGreaterEqual(saved["analyzed_at_ns"], after[0])
        self.assertEqual(saved["timing_confirmed_revision"], saved["revision"])

    def test_reference_no_future_and_late_change_requeues_future_and_preserves_feedback(
        self,
    ):
        for i in range(13):
            self.publish(T + i * FIVE)
            self.analyze_at(T + i * FIVE)
        start = T + 13 * FIVE
        self.publish(start, n=100)
        self.analyze_at(start)
        self.assertGreater(self.count("findings"), 0)
        f = self.db.conn.execute(
            "SELECT * FROM " + self.config.ad_schema + ".findings LIMIT 1"
        ).fetchone()
        self.db.conn.execute(
            "INSERT INTO "
            + self.config.ad_schema
            + ".feedback(finding_id,finding_revision,verdict,note,recorded_at_ns) VALUES(%s,%s,%s,%s,%s)",
            (f["finding_id"], f["revision"], "CONFIRMED", "retain", time.time_ns()),
        )
        signature = self.db.conn.execute(
            "SELECT summary_hash FROM "
            + self.config.ad_schema
            + ".window_results WHERE start_ns=%s",
            (T,),
        ).fetchone()["summary_hash"]
        self.db.publish(
            "test", T, T + FIVE, extract([row("r" + str(T) + "-0", session="other")]), 1
        )
        self.analyze_at(T)
        self.assertNotEqual(
            signature,
            self.db.conn.execute(
                "SELECT summary_hash FROM "
                + self.config.ad_schema
                + ".window_results WHERE start_ns=%s",
                (T,),
            ).fetchone()["summary_hash"],
        )
        self.assertGreater(
            self.db.conn.execute(
                "SELECT count(*) AS n FROM "
                + self.config.ad_schema
                + ".reanalysis WHERE processed_version<version"
            ).fetchone()["n"],
            0,
        )
        self.assertEqual(self.count("feedback"), 1)
        while self.db.step("test")["status"] != "ANALYSIS_IDLE":
            pass
        self.assertEqual(self.count("feedback"), 1)

    def test_pending_expires_without_fake_behavior_and_late_completion_reuses_state(
        self,
    ):
        self.db.publish(
            "test",
            T,
            T + FIVE,
            extract(
                [
                    row(
                        "pending",
                        path="ClientAyanCoInquiry.WaterBillInquiry",
                        message='Input:{"BillID":"old"}',
                    )
                ]
            ),
            1,
        )
        for i in range(1, 8):
            self.db.publish("test", T + i * FIVE, T + (i + 1) * FIVE, {}, 0)
        p = self.db.conn.execute(
            "SELECT * FROM " + self.config.source_schema + ".pending_requests"
        ).fetchone()
        self.assertEqual(p["status"], "EXPIRED")
        self.assertEqual(self.count("behaviors", True), 0)
        self.db.publish(
            "test",
            T + 8 * FIVE,
            T + 9 * FIVE,
            extract([row("pending", at=iso(T + 8 * FIVE + 10**9))]),
            1,
        )
        self.assertEqual(self.count("pending_requests", True), 0)
        b = self.db.conn.execute(
            "SELECT * FROM " + self.config.source_schema + ".behaviors"
        ).fetchone()
        self.assertEqual(b["features"]["input"]["targets"]["BillID"][0]["value"], "old")

    def test_backfill_does_not_rewind_cursor_or_allow_unbounded_replay(self):
        self.publish(T + 20 * FIVE)
        self.publish(T + 5 * FIVE, allow_history=True)
        self.assertEqual(self.db.cursor("test"), T + 21 * FIVE)
        with self.assertRaisesRegex(ValueError, "24_hours"):
            self.publish(T - 300 * FIVE, allow_history=True)

    def test_manual_web_session_payload_anomaly_feedback_and_no_refresh_timer(self):
        self.publish()
        self.analyze_at(T)
        app = create_app(self.config, self.database, "test", secret="disposable-test")
        client = app.test_client()
        for url in ("/", "/sessions?q=s0", "/incidents", "/api/status", "/healthz"):
            r = client.get(url)
            self.assertEqual(r.status_code, 200, (url, r.data[:200]))
            self.assertNotIn(b"setInterval", r.data)
            self.assertNotIn(b'http-equiv="refresh"', r.data)
        bid = self.db.conn.execute(
            "SELECT behavior_id FROM "
            + self.config.source_schema
            + ".behaviors LIMIT 1"
        ).fetchone()["behavior_id"]
        self.assertEqual(client.get("/behaviors/" + bid).status_code, 200)
        self.assertEqual(client.get("/sessions?q=s0&before=bad").status_code, 400)
        self.assertEqual(
            client.post(
                "/incidents/missing/feedback", data={"verdict": "CONFIRMED"}
            ).status_code,
            400,
        )

    def test_empty_source_window_is_acknowledged_as_insufficient(self):
        self.db.publish("test", T, T + FIVE, {}, 0)
        result = self.db.step("test")
        self.assertEqual(result["status"], "ANALYSIS_COMMITTED")
        self.assertEqual(result["anomalies"], 0)
        self.assertTrue(
            all(
                set(counts) == {"INSUFFICIENT_DATA"}
                for counts in result["counts"].values()
            )
        )

    def test_lease_duplicate_and_stop_token_fence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "viewer_config.local.py").write_text(
                "DATABASE="
                + repr(self.database)
                + '\nELASTICSEARCH={"host":"http://example.test","index_pattern":"logs-*"}'
            )
            (root / "compact_product.local.json").write_text(
                json.dumps(
                    dict(
                        source_schema=self.config.source_schema,
                        ad_schema=self.config.ad_schema,
                    )
                )
            )
            lease = Lease(root, "ingest", "one")
            try:
                with self.assertRaisesRegex(ValueError, "ALREADY_RUNNING"):
                    Lease(root, "ingest", "two")
                value = status(root)
                self.assertTrue(value["ingest"]["running"])
                self.assertEqual(value["ingest"]["command_token"], "one")
                lease.stop_file.write_text('{"token":"old"}')
                time.sleep(2.2)
                self.assertFalse(lease.stop.is_set())
                lease.stop_file.write_text('{"token":"one"}')
                self.assertTrue(lease.stop.wait(4))
            finally:
                lease.close()
            self.assertFalse(status(root)["ingest"]["running"])

    def test_concurrent_runtime_catalog_initialization_is_serialized(self):
        import threading
        barrier = threading.Barrier(6)
        def initialize(_):
            db = Store(self.database, schema=self.config.source_schema)
            try:
                barrier.wait(timeout=10)
                runtime_init(db.conn, self.config.source_schema)
                return db.conn.execute("SELECT to_regclass(%s) AS name", (self.config.source_schema + ".runtime_roles",)).fetchone()["name"]
            finally:
                db.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            result = list(pool.map(initialize, range(6)))
        self.assertTrue(all(name for name in result))

    def test_large_content_does_not_block_three_commits_or_duplicate_a_replay(self):
        for index in range(3):
            start = T + index * FIVE
            key = "large-" + str(index)
            records = [row(key, at=iso(start + 10**9)), row(key, message='Input:{"BillID":"W","Amount":1,"Description":"' + 'x' * 400000 + '"}', at=iso(start + 10**9))]
            states = extract(records)
            self.db.publish("test", start, start + FIVE, states, len(records))
            self.analyze_at(start)
            replay = self.db.publish("test", start, start + FIVE, states, len(records))
            self.assertEqual((replay["inserted"], replay["updated"]), (0, 0))
        self.assertEqual(self.db.cursor("test"), T + 3 * FIVE)
        self.assertEqual(self.count("behaviors", True), 3)
        self.assertEqual(self.count("window_results"), 3)
        self.assertEqual(self.db.conn.execute(f"SELECT dirty_keys FROM {self.config.source_schema}.queue_counts WHERE stream_id='test'").fetchone()["dirty_keys"], 0)

    def test_default_web_shows_actions_and_keeps_auxiliary_and_unknown_views_separate(self):
        records = [row("water-inquiry", "s0"), row("support-config", "s0", path="Core.v1/ConfigBasic"), row("support-list", "s0", path="Core.v1/UserServiceQueries"), row("unknown-route", "s0", path="Services.v99/NewUnknown")]
        records += [row("dispatch-water", "s0", path="Services.v1/InvoiceRegister"), row("dispatch-water", "s0", path="DBPath.pishkhan24.application.ud_prc_userSessionHasAccess", message="(SQL Parameters: @action=v1/WaterBills)"), row("dispatch-water", "s0", path="DBPath.pishkhan24.application.ud_prc_invoiceRequest", message="(SQL Parameters: @serviceID=7)")]
        records += [row("unresolved-dispatch", "s0", path="Services.v1/InvoiceRegister")]
        self.db.publish("test", T, T + FIVE, extract(records), len(records))
        app = create_app(self.config, self.database, "test")
        client = app.test_client()
        for url in ("/", "/sessions?q=s0"):
            default = client.get(url).get_data(as_text=True)
            self.assertIn("water-inquiry", default)
            self.assertIn("dispatch-water", default)
            self.assertIn("Services.v1/WaterBills", default)
            self.assertNotIn("استعلام قبض آب", default)
            if url == "/":
                self.assertIn('href="/?scope=all"',default)
            self.assertNotIn("support-config", default)
            self.assertNotIn("support-list", default)
            self.assertNotIn("unknown-route", default)
            self.assertNotIn("unresolved-dispatch", default)
            all_rows = client.get(url + ("&" if "?" in url else "?") + "scope=all").get_data(as_text=True)
            self.assertTrue(all(key in all_rows for key in ("support-config", "support-list", "unknown-route")))
        unknown = client.get("/?scope=unknown").get_data(as_text=True)
        self.assertIn("unknown-route", unknown)
        self.assertIn("unresolved-dispatch", unknown)
        self.assertNotIn("water-inquiry", unknown)
        self.assertNotIn("dispatch-water", unknown)

    def test_old_model_is_rebuilt_from_facts_and_not_reused_as_a_current_reference(self):
        from compact_ad import MODEL
        self.publish()
        self.analyze_at(T)
        self.db.conn.execute(f"UPDATE {self.config.ad_schema}.window_results SET model_version='previous-model' WHERE stream_id='test'")
        previous_epoch = self.db.conn.execute(f"SELECT epoch FROM {self.config.ad_schema}.reference_epochs WHERE stream_id='test'").fetchone()["epoch"]
        self.assertEqual(self.db.select_work("test"), T)
        work = self.db.snapshot("test", T)
        self.assertEqual(work["references"], [])
        self.assertIsNotNone(work["job"])
        self.db.step("test")
        current = self.db.conn.execute(f"SELECT model_version FROM {self.config.ad_schema}.window_results WHERE stream_id='test'").fetchone()
        self.assertEqual(current["model_version"], MODEL)
        self.assertGreater(self.db.conn.execute(f"SELECT epoch FROM {self.config.ad_schema}.reference_epochs WHERE stream_id='test'").fetchone()["epoch"], previous_epoch)
        self.assertGreater(self.count("summary_history"), 0)


if __name__ == "__main__":
    unittest.main()
