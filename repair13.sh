#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
bad(){ printf '%s FAIL %s%s\n' "$R" "$N" "$*"; }
FAILED=0

echo "=== 1. ctx.evidence wired? ==="
grep -q "evidence=self.evidence" core/engine.py && ok "wired" \
  || { bad "NOT wired"; FAILED=$((FAILED+1)); }

echo "=== 2. order in run_scan ==="
grep -n "EvidenceStore(\|TargetEngine(" main.py | sed 's/^/  /'

python - <<'PYEOF'
import pathlib, re, sys
p = pathlib.Path("main.py")
lines = p.read_text().splitlines(keepends=True)
ev = next((i for i, l in enumerate(lines) if "evidence = EvidenceStore(" in l), None)
en = next((i for i, l in enumerate(lines) if "engine = TargetEngine(" in l), None)
if ev is None or en is None:
    print("  MISS anchors", ev, en); sys.exit(1)
if ev > en:
    block = lines[ev:ev + 2]
    del lines[ev:ev + 2]
    lines[en:en] = block
    p.write_text("".join(lines))
    print("  ok   EvidenceStore moved above TargetEngine")
else:
    print("  skip order (already correct)")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 3. smoke test: real run_scan against a local server ==="
cat > tests/test_scan_smoke.py <<'SMKEOF'
"""End-to-end smoke test: run_scan against a local fixture, assert the DB."""
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

    def tearDown(self):
        self.srv.shutdown()

    def _runtime(self, tmp: Path):
        cfg = Config()
        cfg.set("scope.allow_private_targets", True)
        cfg.set("tools.mode", "off")
        cfg.set("infra.enable_nmap", False)
        cfg.set("infra.enable_whois", False)
        cfg.set("scan.concurrency_targets", 1)
        cfg.set("safety.notify_on_complete", False)
        app.RUNTIME.update({
            "config": cfg,
            "db": Database(tmp / "t.db"),
            "reports": ReportManager(tmp / "reports", BASE / "templates" / "report.html"),
            "stop": asyncio.Event(),
            "active_scan": None,
        })
        return app.RUNTIME["db"]

    async def test_full_scan_marks_done_and_writes_reports(self):
        with tempfile.TemporaryDirectory(dir=BASE / "tests") as d:
            tmp = Path(d)
            db = self._runtime(tmp)
            try:
                await app.run_scan([self.url], "smoke", auto_reports=True)
            finally:
                db.close()

            scan_id = app.RUNTIME["active_scan"] or db.recent_scans(1)[0]["id"]
            scan_id = db.recent_scans(1)[0]["id"]
            targets = db.targets(scan_id)
            self.assertEqual(len(targets), 1)
            self.assertEqual(targets[0]["status"], "done",
                             f"status was {targets[0]['status']} err={targets[0]['error']}")
            self.assertGreater(len(db.findings(scan_id)), 0, "no findings recorded")
            html = list((tmp / "reports" / "html").glob("*.html"))
            self.assertTrue(html, "no html report written")
            self.assertIn("TSMSS", html[0].read_text())

    async def test_second_scan_after_failure_keeps_running(self):
        with tempfile.TemporaryDirectory(dir=BASE / "tests") as d:
            tmp = Path(d)
            db = self._runtime(tmp)
            dead = "http://127.0.0.1:1/"
            try:
                await app.run_scan([dead, self.url], "smoke", auto_reports=False)
            finally:
                db.close()
            scan_id = db.recent_scans(1)[0]["id"]
            statuses = {t["url"]: t["status"] for t in db.targets(scan_id)}
            self.assertEqual(statuses[self.url], "done")


if __name__ == "__main__":
    unittest.main(verbosity=2)
SMKEOF

echo "=== 4. compile + selftest + full suite ==="
python -m compileall -q core modules ui main.py config.py 2>&1 | tail -5
python tests/selftest.py || { bad selftest; FAILED=$((FAILED+1)); }
python -m unittest discover tests 2>&1 | grep -E '^(FAIL|ERROR|OK|Ran |FAILED)' || true
python -m unittest discover tests >/dev/null 2>&1 || { bad "unit tests"; FAILED=$((FAILED+1)); }

echo
if [ "$FAILED" -eq 0 ]; then printf '%sAll green.%s\n' "$G" "$N"
else printf '%s%d issue(s).%s\n' "$R" "$FAILED" "$N"; exit 1; fi
