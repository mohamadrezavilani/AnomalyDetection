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


if __name__ == "__main__":
    unittest.main()
