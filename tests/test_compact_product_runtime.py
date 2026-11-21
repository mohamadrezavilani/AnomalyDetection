from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import tempfile
import threading
import time
import unittest
from compact_behavior.extract import instant, iso
from compact_behavior import FIVE
from compact_product.runtime import start, stop, status
from compact_product.operations import observe
from tests.test_compact_extract import row, scroll_packet
from tests import test_compact_product_pg as fixture


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def elastic_server():
    sessions = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, status, body):
            packet = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(packet)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(packet)

        def do_POST(self):
            body = json.loads(
                self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}"
            )
            if "_pit?" in self.path:
                return self.respond(
                    400, {"error": {"type": "illegal_argument_exception"}}
                )
            if self.path.startswith("/_search/scroll"):
                sid = body["scroll_id"]
                return self.respond(200, scroll_packet(sid, [], sessions[sid]))
            at = body["query"]["range"]["@timestamp"]["gte"]
            start_ns = instant(at)
            records = []
            for i in range(12):
                key = "r" + str(start_ns) + "-" + str(i)
                session = "s" + str(i // 2)
                records.extend(
                    [
                        row(key, session, at=iso(start_ns + 10**9)),
                        row(
                            key,
                            session,
                            at=iso(start_ns + 10**9),
                            message='Input:{"BillID":"'
                            + str(i)
                            + '"} Output:{"Amount":10}',
                        ),
                    ]
                )
            sid = str(start_ns)
            sessions[sid] = len(records)
            docs = [
                dict(_index="logs-test", _id=str(i), _source=r)
                for i, r in enumerate(records)
            ]
            return self.respond(200, scroll_packet(sid, docs, len(docs), initial=True))

        def do_DELETE(self):
            return self.respond(200, {"succeeded": True})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


@unittest.skipUnless(os.environ.get("P24_DELTA_PG_HOST"), "native PostgreSQL required")
class CompactRuntimeTests(unittest.TestCase):
    setUp = fixture.CompactProductPostgresTests.setUp
    tearDown = fixture.CompactProductPostgresTests.tearDown

    def test_actual_three_processes_receive_analyze_serve_restart_and_browser(self):
        with tempfile.TemporaryDirectory() as directory, elastic_server() as url:
            root = Path(directory)
            port = free_port()
            second = free_port()
            (root / "viewer_config.local.py").write_text(
                "DATABASE="
                + repr(self.database)
                + "\nELASTICSEARCH="
                + repr({"host": url, "index_pattern": "logs-*"}),
                encoding="utf-8",
            )
            (root / "compact_product.local.json").write_text(
                json.dumps(
                    dict(
                        source_schema=self.config.source_schema,
                        ad_schema=self.config.ad_schema,
                        host="127.0.0.1",
                        web_ports=[port, second],
                        reference_windows=13,
                        overlap_windows=0,
                    )
                ),
                encoding="utf-8",
            )
            try:
                state = start(root)
                self.assertTrue(
                    all(v["running"] for r, v in state.items() if r != "supervisor")
                )
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline:
                    result = self.db.conn.execute(
                        "SELECT count(*) AS n FROM "
                        + self.config.ad_schema
                        + ".window_results"
                    ).fetchone()["n"]
                    if (
                        result >= 13
                        and status(root)["ingest"].get("state")
                        == "WAITING_FOR_CLOSED_WINDOW"
                    ):
                        break
                    time.sleep(0.3)
                self.assertGreaterEqual(result, 13)
                from compact_product.operations import probe

                self.assertEqual(
                    len(
                        probe(
                            __import__("dataclasses").replace(
                                self.config, host="127.0.0.1", web_ports=(port, second)
                            )
                        )
                    ),
                    2,
                )
                bid = self.db.conn.execute(
                    "SELECT behavior_id FROM "
                    + self.config.source_schema
                    + ".behaviors LIMIT 1"
                ).fetchone()["behavior_id"]
                # A real source revision creates explainable findings after
                # the strictly prior reference windows have been consumed.
                source = self.db.conn.execute(
                    "SELECT stream_id,next_ns FROM "
                    + self.config.source_schema
                    + ".streams"
                ).fetchone()
                target = source["next_ns"] - FIVE
                records = []
                for i in range(100):
                    key = "attack-" + str(i)
                    records.extend(
                        [
                            row(key, "attack", at=iso(target + 10**9)),
                            row(
                                key,
                                "attack",
                                at=iso(target + 10**9),
                                message='Input:{"BillID":"'
                                + str(i)
                                + '"} Output:{"Amount":10}',
                            ),
                        ]
                    )
                self.db.publish(
                    source["stream_id"],
                    target,
                    target + FIVE,
                    __import__(
                        "tests.test_compact_extract", fromlist=["extract"]
                    ).extract(records),
                    len(records),
                )
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    findings = self.db.conn.execute(
                        "SELECT count(*) AS n FROM "
                        + self.config.ad_schema
                        + ".findings"
                    ).fetchone()["n"]
                    if findings:
                        break
                    time.sleep(0.2)
                self.assertGreater(findings, 0)
                if os.environ.get("P24_COMPACT_BROWSER"):
                    from playwright.sync_api import sync_playwright

                    with sync_playwright() as p:
                        browser = p.chromium.launch(
                            executable_path=os.environ["P24_COMPACT_BROWSER"],
                            headless=True,
                            args=["--no-sandbox", "--disable-dev-shm-usage"],
                        )
                        page = browser.new_page(viewport=dict(width=1400, height=1000))
                        errors = []
                        page.on("pageerror", lambda e: errors.append(str(e)))
                        page.goto(f"http://127.0.0.1:{port}/")
                        page.get_by_role(
                            "link", name="جست‌وجوی نشست", exact=True
                        ).click()
                        page.locator("input[name=q]").fill("s0")
                        page.get_by_role("button", name="جست‌وجو", exact=True).click()
                        self.assertGreater(page.locator("table td").count(), 0)
                        page.goto(f"http://127.0.0.1:{port}/behaviors/{bid}")
                        self.assertIn("Amount", page.locator("body").inner_text())
                        page.goto(f"http://127.0.0.1:{port}/incidents")
                        self.assertIn("موارد قابل بررسی", page.title())
                        page.locator("table a").first.click()
                        page.locator("select[name=verdict]").select_option("CONFIRMED")
                        page.locator("textarea[name=note]").fill(
                            "synthetic browser verification"
                        )
                        page.get_by_role("button", name="ثبت نظر").click()
                        self.assertIn(
                            "synthetic browser verification",
                            page.locator("body").inner_text(),
                        )
                        self.assertEqual(errors, [])
                        screenshot = os.environ.get("P24_COMPACT_SCREENSHOT")
                        if screenshot:
                            page.goto(f"http://127.0.0.1:{port}/")
                            page.screenshot(path=screenshot, full_page=True)
                        browser.close()
                observation = observe(root, 10, root)
                self.assertEqual(observation["status"], "COMPACT_OBSERVATION_COMPLETE")
                before = self.db.cursor(
                    next(
                        iter(
                            self.db.conn.execute(
                                "SELECT stream_id FROM "
                                + self.config.source_schema
                                + ".streams"
                            )
                        )
                    )["stream_id"]
                )
                stop(root)
                self.assertTrue(all(not v["running"] for v in status(root).values()))
                start(root)
                self.assertGreaterEqual(
                    self.db.cursor(
                        next(
                            iter(
                                self.db.conn.execute(
                                    "SELECT stream_id FROM "
                                    + self.config.source_schema
                                    + ".streams"
                                )
                            )
                        )["stream_id"]
                    ),
                    before,
                )
            finally:
                stop(root, timeout=30)


if __name__ == "__main__":
    unittest.main()
