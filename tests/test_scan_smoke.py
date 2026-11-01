"""End-to-end smoke test: run_scan against a local fixture, assert the DB.

Rate limits are opened up so the whole thing finishes in seconds; the
modules that need real DNS or TLS are disabled because the fixture is
127.0.0.1.
"""
import asyncio
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import main as app
from config import Config
from core.database import Database
from core.report_manager import ReportManager

PAGE = b"<html><head><title>t</title></head><body>ok</body></html>"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(PAGE)))
        self.send_header("Set-Cookie", "sid=abc; Path=/")
        self.end_headers()
        self.wfile.write(PAGE)


class TestRunScanSmoke(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.port}/"
        self.tmp = tempfile.TemporaryDirectory(dir=BASE / "tests")
        self.db = None

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        if self.db is not None:
            try:
                self.db.close()
            except Exception:
                pass
        self.tmp.cleanup()

    def _runtime(self):
        tmp = Path(self.tmp.name)
        cfg = Config()
        cfg.set("scope.allow_private_targets", True)
        cfg.set("tools.mode", "off")
        cfg.set("infra.enable_nmap", False)
        cfg.set("infra.enable_whois", False)
        cfg.set("safety.notify_on_complete", False)
        cfg.set("scan.concurrency_targets", 1)
        # fixture is local: no need to be polite to it
        cfg.set("scan.max_requests_per_second", 200.0)
        cfg.set("scan.per_host_requests_per_second", 200.0)
        cfg.set("scan.delay_between_requests", 0)
        cfg.set("scan.request_timeout", 5)
        cfg.set("scan.module_timeout", 15)
        cfg.set("active.max_params_per_target", 3)
        cfg.set("modules.disabled", ["dns_security", "ssl_tls", "infrastructure"])
        self.db = Database(tmp / "t.db")
        app.RUNTIME.update({
            "config": cfg,
            "db": self.db,
            "reports": ReportManager(tmp / "reports", BASE / "templates" / "report.html"),
            "stop": asyncio.Event(),
            "active_scan": None,
        })
        return self.db

    async def test_full_scan_marks_done_and_writes_reports(self):
        db = self._runtime()
        await app.run_scan([self.url], "smoke", auto_reports=True)

        scan_id = db.recent_scans(1)[0]["id"]
        targets = db.targets(scan_id)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["status"], "done",
                         f"status={targets[0]['status']} err={targets[0]['error']}")
        self.assertGreater(len(db.findings(scan_id)), 0, "no findings recorded")

        html = list((Path(self.tmp.name) / "reports" / "html").glob("*.html"))
        self.assertTrue(html, "no html report written")
        self.assertIn("TSMSS", html[0].read_text())

    async def test_failure_does_not_stop_the_batch(self):
        db = self._runtime()
        await app.run_scan(["http://127.0.0.1:1/", self.url], "smoke", auto_reports=False)

        scan_id = db.recent_scans(1)[0]["id"]
        statuses = {t["url"]: t["status"] for t in db.targets(scan_id)}
        self.assertEqual(statuses[self.url], "done")

    async def test_score_is_not_floored_by_noise(self):
        db = self._runtime()
        await app.run_scan([self.url], "smoke", auto_reports=False)
        scan_id = db.recent_scans(1)[0]["id"]
        row = db.targets(scan_id)[0]
        self.assertIsNotNone(row["score"])
        self.assertGreater(row["score"], 0, "score floored at 0 by header noise")

    async def test_resume_unfinished_targets_from_sqlite(self):
        from core.finding import Finding

        db = self._runtime()
        cfg = app.RUNTIME["config"]
        done_url = "http://127.0.0.1:9999/"
        scan_id = db.create_scan(cfg.data, 2, "interrupted-batch")
        db.add_targets(scan_id, [done_url, self.url])
        db.set_target_status(scan_id, done_url, "done", score=95, requests=4)
        db.add_findings(scan_id, [
            Finding(
                target=done_url,
                category="HTTP Security",
                title="Pre-existing finding on finished target",
                severity="LOW",
                description="Already recorded before interruption.",
                evidence="HTTP/1.1 200 OK",
                module="http_security",
                confidence="CONFIRMED",
            )
        ])
        db.finish_scan(scan_id, "interrupted")

        resumed_id = await app.run_scan(
            [],
            "resume-smoke",
            auto_reports=False,
            resume_scan_id=scan_id,
        )
        self.assertEqual(resumed_id, scan_id)
        statuses = {t["url"]: t["status"] for t in db.targets(scan_id)}
        self.assertEqual(statuses[done_url], "done")
        self.assertEqual(statuses[self.url], "done")
        findings_done = db.findings(scan_id, target=done_url)
        findings_resumed = db.findings(scan_id, target=self.url)
        self.assertEqual(len(findings_done), 1)
        self.assertGreater(len(findings_resumed), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
