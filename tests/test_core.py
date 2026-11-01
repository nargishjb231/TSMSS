import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.finding import Finding, severity_rank
from core.validator import normalize, validate, load_targets
from core.scope import ScopeGuard, is_private_ip
from core.engine import score
from core.evidence import EvidenceStore
from core.context import Target


class TestValidator(unittest.TestCase):
    def test_scheme_added(self):
        self.assertEqual(normalize("example.com"), "https://example.com/")

    def test_default_port_stripped(self):
        self.assertEqual(normalize("https://example.com:443/a"), "https://example.com/a")

    def test_reject_schemes(self):
        for bad in ("ftp://x.com", "javascript:alert(1)", "data:text/html,x"):
            self.assertFalse(validate(bad).valid, bad)

    def test_reject_space(self):
        self.assertFalse(validate("http://bad host.com").valid)

    def test_strips_invisible_characters(self):
        for junk in ("\u200e", "\u200b", "\ufeff", "\u00a0", "\u00ad", "\u200f"):
            self.assertEqual(normalize(f"{junk}https://example.com/"),
                             "https://example.com/", repr(junk))
            self.assertTrue(validate(f"{junk}https://example.com/").valid, repr(junk))

    def test_dedupe(self):
        import tempfile
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            p = Path(d) / "t.txt"
            p.write_text("example.com\nhttps://example.com/\n# c\n\nbad host\n")
            ok, rej = load_targets(p)
        self.assertEqual(ok, ["https://example.com/"])
        self.assertTrue(any(r["reason"] == "duplicate" for r in rej))


class TestScope(unittest.TestCase):
    def test_subdomain_match(self):
        g = ScopeGuard(["example.com"], allow_private=True)
        self.assertTrue(g.check_target("https://a.example.com/").allowed)

    def test_outside_blocked(self):
        g = ScopeGuard(["example.com"], allow_private=True)
        self.assertFalse(g.check_target("https://evil.net/").allowed)

    def test_private_ip(self):
        self.assertTrue(is_private_ip("10.0.0.5"))
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertFalse(is_private_ip("1.1.1.1"))

    def test_redirect_escape(self):
        g = ScopeGuard(["example.com"], allow_private=True)
        self.assertFalse(g.check_redirect("https://example.com/", "https://evil.net/").allowed)
        self.assertTrue(g.check_redirect("https://example.com/", "https://x.example.com/").allowed)


class TestFindings(unittest.TestCase):
    def test_confidence_coerced(self):
        f = Finding(target="t", category="c", title="x", severity="LOW",
                    description="d", confidence="CONFIRMED")
        f.downgrade_if_heuristic("heuristic")
        self.assertEqual(f.confidence, "HIGH CONFIDENCE")

    def test_positive_keeps_confirmed(self):
        f = Finding(target="t", category="c", title="x", severity="LOW",
                    description="d", confidence="CONFIRMED")
        f.downgrade_if_heuristic("missing_header")
        self.assertEqual(f.confidence, "CONFIRMED")

    @staticmethod
    def _rows(sev, n):
        return [Finding(target="t", category="c", title=str(i), severity=sev,
                        description="d") for i in range(n)]

    def test_clean_target_scores_perfect(self):
        self.assertEqual(score([]), (100, "A"))

    def test_score_is_monotonic(self):
        self.assertGreater(score(self._rows("HIGH", 1))[0],
                           score(self._rows("HIGH", 20))[0])

    def test_severe_target_reaches_f(self):
        value, grade = score(self._rows("CRITICAL", 50))
        self.assertEqual(grade, "F")
        self.assertGreaterEqual(value, 0)

    def test_repeats_cost_less_than_first_occurrence(self):
        first = 100 - score(self._rows("MEDIUM", 1))[0]
        extra = score(self._rows("MEDIUM", 1))[0] - score(self._rows("MEDIUM", 10))[0]
        self.assertLess(extra, first * 9)

    def test_severity_order(self):
        self.assertLess(severity_rank("CRITICAL"), severity_rank("LOW"))


class TestEvidence(unittest.TestCase):
    def test_truncation_and_dedupe(self):
        import tempfile
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            ev = Path(d) / "evidence"
            es = EvidenceStore(ev, max_bytes=20)
            a = es.save("lbl", "x" * 100)
            b = es.save("lbl", "x" * 100)
            self.assertEqual(a, b, "repeat save must return the identical path")
            self.assertTrue(a.startswith("evidence/"), a)
            files = sorted(ev.glob("*.txt"))
            self.assertEqual(len(files), 1, f"expected 1 deduped file, got {len(files)}")
            self.assertIn("truncated", files[0].read_text())

    def test_derives_prefix_from_store_directory(self):
        import tempfile
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            custom = Path(d) / "custom_captures"
            es = EvidenceStore(custom, max_bytes=200)
            rel = es.save("probe", "response body")
            self.assertTrue(rel.startswith("custom_captures/"), rel)
            self.assertTrue((Path(d) / rel).exists())



class TestTarget(unittest.TestCase):
    def test_root_is_string(self):
        t = Target("https://example.com/a/b?x=1")
        self.assertIsInstance(t.root, str)
        self.assertEqual(t.root, "https://example.com/")

    def test_root_keeps_port(self):
        self.assertEqual(Target("http://h:8080/a").root, "http://h:8080/")

    def test_https_url_upgrades_scheme(self):
        self.assertEqual(Target("http://example.com/a").https_url, "https://example.com/a")

    def test_https_url_drops_default_port(self):
        self.assertEqual(Target("http://example.com:80/a").https_url, "https://example.com/a")


class TestHttpFetchedHeaders(unittest.TestCase):
    def test_get_all_returns_multi_value_headers(self):
        import httpx
        from core.http_client import Fetched, _extract_multi_headers
        raw = httpx.Headers([
            ("Set-Cookie", "a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT"),
            ("Set-Cookie", "b=2; Path=/; HttpOnly"),
            ("X-Frame-Options", "SAMEORIGIN"),
            ("X-Frame-Options", "DENY"),
        ])
        f = Fetched(
            url="https://example.com/",
            status=200,
            headers={k.lower(): v for k, v in raw.items()},
            body="",
            elapsed_ms=1.0,
            multi_headers=_extract_multi_headers(raw),
        )
        self.assertEqual(len(f.get_all("set-cookie")), 2)
        self.assertIn("Expires=Wed, 21 Oct 2026 07:28:00 GMT", f.get_all("set-cookie")[0])
        self.assertEqual(f.get_all("X-Frame-Options"), ["SAMEORIGIN", "DENY"])
        self.assertEqual(f.get_all("missing-header"), [])


class TestScheduler(unittest.TestCase):
    def test_batch_size_dispatches_in_chunks_and_stops_between_batches(self):
        import asyncio
        from config import Config
        from core.scheduler import Scheduler

        cfg = Config({"scan": {"concurrency_targets": 2, "batch_size": 2}})
        stop = asyncio.Event()
        done_urls = []
        active_peaks = []
        in_flight = 0

        async def on_done(url, result):
            done_urls.append(url)
            if len(done_urls) == 2:
                stop.set()

        async def worker(url):
            nonlocal in_flight
            in_flight += 1
            active_peaks.append(in_flight)
            await asyncio.sleep(0.01)
            in_flight -= 1
            from core.engine import TargetScanResult
            return TargetScanResult(url=url, findings=[], score=100, grade="A", requests=1, ok=True)

        sched = Scheduler(cfg, stop, on_done)
        asyncio.run(sched.run(["https://a.test/", "https://b.test/", "https://c.test/", "https://d.test/"], worker))
        self.assertEqual(done_urls, ["https://a.test/", "https://b.test/"])
        self.assertEqual(sched.state.completed, 2)
        self.assertEqual(sched.state.skipped, 2)
        self.assertEqual(sched.state.pending, 0)
        self.assertLessEqual(max(active_peaks), 2)


class TestConfigAndSettingsMenu(unittest.TestCase):
    def test_validate_modules_and_tools(self):
        from config import Config
        cfg = Config()
        self.assertEqual(cfg.validate(), [])

        cfg.set("modules.disabled", ["ssl_tls", "bogus_mod"])
        errs = cfg.validate()
        self.assertTrue(any("modules.disabled" in e and "bogus_mod" in e for e in errs), errs)

        cfg.set("modules.disabled", ["ssl_tls"])
        cfg.set("tools.mode", "invalid_mode")
        cfg.set("tools.max_runtime", 1)
        cfg.set("tools.rate_limit", 0)
        cfg.set("tools.enabled", ["unknown_tool_xyz"])
        errs2 = cfg.validate()
        self.assertTrue(any("tools.mode" in e for e in errs2), errs2)
        self.assertTrue(any("tools.max_runtime" in e for e in errs2), errs2)
        self.assertTrue(any("tools.rate_limit" in e for e in errs2), errs2)
        self.assertTrue(any("tools.enabled" in e for e in errs2), errs2)

    def test_settings_menu_exposes_modules_and_tools_with_rollback(self):
        from unittest.mock import patch
        import main
        from config import Config

        cfg = Config()
        main.RUNTIME["config"] = cfg
        self.assertIn("modules.disabled", main.SETTINGS_KEYS)
        for tk in ("tools.mode", "tools.max_runtime", "tools.rate_limit",
                   "tools.allow_root_tools", "tools.enabled", "tools.disabled"):
            self.assertIn(tk, main.SETTINGS_KEYS)

        # Edit modules.disabled and tools.mode, then rollback
        responses = iter([
            "modules.disabled",
            "ssl_tls, dns_security",
            "tools.mode",
            "off",
            "rollback",
        ])
        with patch.object(main.Prompt, "ask", side_effect=lambda *a, **kw: next(responses)):
            main.handle_settings()
        self.assertEqual(cfg.get("modules.disabled"), [])
        self.assertEqual(cfg.get("tools.mode"), "auto")

        # Edit to invalid value, attempt save, confirm rollback on validation error
        responses_invalid = iter([
            "modules.disabled",
            "not_a_real_module",
            "",
        ])
        with patch.object(main.Prompt, "ask", side_effect=lambda *a, **kw: next(responses_invalid)), \
             patch.object(main.Confirm, "ask", return_value=True):
            main.handle_settings()
        self.assertEqual(cfg.get("modules.disabled"), [])


class TestTargetScanResultDataclass(unittest.TestCase):
    def test_engine_returns_typed_dataclass_and_report_manager_accepts_it(self):
        import asyncio
        import tempfile
        from config import Config
        from core.engine import TargetEngine, TargetScanResult, MODULE_ORDER
        from core.report_manager import ReportManager
        from core.scope import ScopeGuard

        cfg = Config({"modules": {"disabled": list(MODULE_ORDER)}})
        scope = ScopeGuard([], allow_private=True)

        class DummyHttp:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

        engine = TargetEngine(cfg, {}, scope, lambda stop, counter: DummyHttp())
        res = asyncio.run(engine.scan("https://example.com/", asyncio.Event()))
        self.assertIsInstance(res, TargetScanResult)
        self.assertEqual(res.url, "https://example.com/")
        self.assertTrue(res.ok)
        self.assertEqual(res.score, 100)
        self.assertEqual(res.grade, "A")
        self.assertEqual(res.error, "")

        base = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            rm = ReportManager(Path(d), base / "templates" / "report.html")
            written = rm.write_target_reports({"id": "s1"}, res, [])
            self.assertTrue(Path(written["json"]).exists())
            self.assertTrue(Path(written["html"]).exists())


class TestCliSubcommands(unittest.TestCase):
    def test_legacy_flags_and_subcommands_scan_list_report_config(self):
        import asyncio
        import tempfile
        from unittest.mock import patch
        import main
        from config import Config
        from core.database import Database
        from core.report_manager import ReportManager

        base = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            tmp = Path(d)
            targets_file = tmp / "targets.txt"
            targets_file.write_text("https://example.com/\nhttps://sub.example.com/\nbad host\n",
                                    encoding="utf-8")

            db = Database(tmp / "test.db")
            try:
                cfg = Config()
                rm = ReportManager(tmp / "reports", base / "templates" / "report.html")
                main.RUNTIME.update({
                    "config": cfg,
                    "db": db,
                    "reports": rm,
                    "stop": asyncio.Event(),
                    "active_scan": None,
                })

                # No args falls through to menu (-1)
                self.assertEqual(main.cli([]), -1)

                # Legacy --list and --dry-run
                self.assertEqual(main.cli(["--list", str(targets_file)]), 0)
                self.assertEqual(main.cli(["--dry-run", str(targets_file)]), 0)

                # Subcommand: list
                self.assertEqual(main.cli(["list", str(targets_file)]), 0)

                # Subcommand: scan --dry-run
                self.assertEqual(main.cli(["scan", "--dry-run", str(targets_file)]), 0)
                self.assertEqual(main.cli(["scan", "-b", str(targets_file), "--dry-run"]), 0)

                # Subcommand: config --validate, --get, --set (with rollback on invalid)
                self.assertEqual(main.cli(["config", "--validate"]), 0)
                self.assertEqual(main.cli(["config", "--get", "tools.mode"]), 0)
                self.assertEqual(main.cli(["config", "--set", "modules.disabled=not_a_module"]), 1)
                self.assertEqual(cfg.get("modules.disabled"), [])
                with patch.object(cfg, "save"):
                    self.assertEqual(main.cli(["config", "--set", "modules.disabled=ssl_tls,dns_security"]), 0)
                self.assertEqual(cfg.get("modules.disabled"), ["ssl_tls", "dns_security"])

                # Subcommand: report
                sid = db.create_scan(cfg.data, 1, "test")
                db.add_targets(sid, ["https://example.com/"])
                db.set_target_status(sid, "https://example.com/", "done", score=100, requests=5)
                db.finish_scan(sid, "complete")
                self.assertEqual(main.cli(["report", sid, "--format", "json"]), 0)
                self.assertTrue(list((tmp / "reports" / "json").glob("*.json")))
            finally:
                db.close()


class TestHttpClientRetryPolicy(unittest.IsolatedAsyncioTestCase):
    async def test_retry_on_429_5xx_and_reset_never_on_other_4xx(self):
        import asyncio
        from unittest.mock import AsyncMock, patch
        import httpx
        from config import Config
        from core.http_client import (
            HttpClient,
            compute_backoff,
            parse_retry_after,
            should_retry_status,
        )
        from core.scope import ScopeGuard

        # 1. Status classification rules
        for code in (408, 429, 500, 502, 503, 504):
            self.assertTrue(should_retry_status(code), f"expected retry for {code}")
        for code in (200, 301, 400, 401, 403, 404, 405, 422):
            self.assertFalse(should_retry_status(code), f"expected no retry for {code}")

        # 2. Retry-After parsing (delta-seconds and HTTP-date)
        self.assertAlmostEqual(parse_retry_after("2.5"), 2.5, places=2)
        self.assertEqual(compute_backoff(0, retry_after="999", max_wait=10.0), 10.0)
        self.assertIsNotNone(parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT"))
        self.assertGreater(compute_backoff(0, backoff_base=0.2), 0.0)

        from core.rate_limiter import RateLimiter
        cfg = Config()
        cfg.set("scope.allow_private_targets", True)
        cfg.set("scan.max_retries", 2)
        cfg.set("scan.max_requests_per_second", 500.0)
        cfg.set("scan.per_host_requests_per_second", 500.0)
        cfg.set("scan.delay_between_requests", 0)
        scope = ScopeGuard([], allow_private=True)
        limiter = RateLimiter(500.0, 500.0)

        async with HttpClient(cfg, scope, limiter, asyncio.Event(), {"requests": 0}) as client:
            # 3. 404 must NEVER retry (exact 1 attempt)
            attempts_404 = 0

            async def fake_request_404(method, url, headers=None, content=None):
                nonlocal attempts_404
                attempts_404 += 1
                req = httpx.Request(method, url)
                return httpx.Response(404, headers={"Content-Type": "text/plain"}, content=b"not found", request=req)

            with patch.object(client._client, "request", side_effect=fake_request_404):
                res = await client.get("http://127.0.0.1:8080/missing")
                self.assertIsNotNone(res)
                self.assertEqual(res.status, 404)
                self.assertEqual(attempts_404, 1)

            # 4. 429 with Retry-After + 503 retries and succeeds on 3rd attempt
            attempts_retry = 0

            async def fake_request_429_503_200(method, url, headers=None, content=None):
                nonlocal attempts_retry
                attempts_retry += 1
                req = httpx.Request(method, url)
                if attempts_retry == 1:
                    return httpx.Response(429, headers={"Retry-After": "0.01"}, content=b"rate limit", request=req)
                if attempts_retry == 2:
                    return httpx.Response(503, headers={}, content=b"busy", request=req)
                return httpx.Response(200, headers={"Content-Type": "text/plain"}, content=b"ok", request=req)

            with patch.object(client._client, "request", side_effect=fake_request_429_503_200):
                res_ok = await client.get("http://127.0.0.1:8080/flaky")
                self.assertIsNotNone(res_ok)
                self.assertEqual(res_ok.status, 200)
                self.assertEqual(attempts_retry, 3)

            # 5. ConnectionResetError retries and succeeds
            attempts_reset = 0

            async def fake_request_reset(method, url, headers=None, content=None):
                nonlocal attempts_reset
                attempts_reset += 1
                if attempts_reset == 1:
                    raise ConnectionResetError("connection reset by peer")
                req = httpx.Request(method, url)
                return httpx.Response(200, headers={}, content=b"recovered", request=req)

            with patch.object(client._client, "request", side_effect=fake_request_reset), \
                 patch("core.http_client.compute_backoff", return_value=0.01):
                res_rec = await client.get("http://127.0.0.1:8080/reset")
                self.assertIsNotNone(res_rec)
                self.assertEqual(res_rec.status, 200)
                self.assertEqual(attempts_reset, 2)


class TestBaselineDiffSarifAndAiPackage(unittest.TestCase):
    def test_baseline_exact_four_tuple_fingerprint(self):
        import tempfile
        from core.verification import filter_by_baseline, load_baseline, save_baseline

        f1 = Finding(
            target="https://example.com/",
            category="HTTP Security",
            title="Missing HSTS",
            severity="MEDIUM",
            description="No Strict-Transport-Security header.",
            evidence="HTTP/1.1 200 OK\nServer: nginx",
            module="http_security",
            parameter="Strict-Transport-Security",
            confidence="CONFIRMED",
        )
        f2_different_evidence = Finding(
            target="https://example.com/",
            category="HTTP Security",
            title="Missing HSTS",
            severity="MEDIUM",
            description="No Strict-Transport-Security header.",
            evidence="HTTP/1.1 200 OK\nServer: apache",
            module="http_security",
            parameter="Strict-Transport-Security",
            confidence="CONFIRMED",
        )
        self.assertEqual(len(f1.fingerprint()), 4)
        self.assertNotEqual(f1.fingerprint(), f2_different_evidence.fingerprint())

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            bpath = Path(d) / "baseline.json"
            save_baseline(bpath, [f1])
            loaded = load_baseline(bpath)
            self.assertIn(f1.fingerprint(), loaded)

            kept, suppressed = filter_by_baseline([f1, f2_different_evidence], loaded)
            self.assertEqual(suppressed, 1)
            self.assertEqual(len(kept), 1)
            self.assertEqual(kept[0].evidence, f2_different_evidence.evidence)

    def test_diff_sarif_and_ai_package_reports(self):
        import json
        import tempfile
        from ai.packager import validate_ai_report
        from core.report_manager import ReportManager, diff_scans

        base = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            tmp = Path(d)
            rm = ReportManager(tmp / "reports", base / "templates" / "report.html")

            f_common = Finding(
                target="https://a.example.com/",
                category="HTTP Security",
                title="Missing CSP",
                severity="MEDIUM",
                description="No Content-Security-Policy header.",
                evidence="HTTP 200 headers: server=nginx",
                module="http_security",
                confidence="CONFIRMED",
                cwe="CWE-693",
            ).to_dict()
            f_fixed = Finding(
                target="https://a.example.com/",
                category="Cookie Security",
                title="Cookie missing HttpOnly",
                severity="LOW",
                description="sid cookie lacks HttpOnly.",
                evidence="Set-Cookie: sid=123; Path=/",
                module="cookie_security",
                parameter="sid",
                confidence="CONFIRMED",
                cwe="CWE-1004",
            ).to_dict()
            f_new = Finding(
                target="https://b.example.com/",
                category="API Security",
                title="API key passed in URL query string",
                severity="HIGH",
                description="Secret token in URL query.",
                evidence="GET /api/v1/items?api_key=secret1234567890",
                module="api_security",
                parameter="api_key",
                confidence="STRONG EVIDENCE",
                cwe="CWE-598",
            ).to_dict()

            targets = [
                {"url": "https://a.example.com/", "status": "done", "score": 92, "grade": "A", "request_count": 10, "duration_s": 1.0},
                {"url": "https://b.example.com/", "status": "done", "score": 85, "grade": "B", "request_count": 12, "duration_s": 1.2},
            ]
            prev_json = rm.json_report({"id": "prev1", "profile": "standard"}, targets, {
                "https://a.example.com/": [f_common, f_fixed],
                "https://b.example.com/": [],
            })
            # Copy prev_json before curr_json overwrites same-second timestamp filename if within 1s
            prev_copy = tmp / "prev_saved.json"
            prev_copy.write_text(prev_json.read_text(encoding="utf-8"), encoding="utf-8")

            curr_json = rm.json_report({"id": "curr2", "profile": "standard"}, targets, {
                "https://a.example.com/": [f_common],
                "https://b.example.com/": [f_new],
            })

            # 1. Validate AI JSON report schema
            payload = json.loads(curr_json.read_text(encoding="utf-8"))
            self.assertEqual(validate_ai_report(payload), [])

            # 2. Scan diffing (new / fixed / still_open per target)
            diff = diff_scans({
                "https://a.example.com/": [f_common],
                "https://b.example.com/": [f_new],
            }, prev_copy)
            self.assertEqual(diff["totals"]["new"], 1)
            self.assertEqual(diff["totals"]["fixed"], 1)
            self.assertEqual(diff["totals"]["still_open"], 1)
            self.assertEqual(len(diff["targets"]["https://a.example.com/"]["fixed"]), 1)
            self.assertEqual(len(diff["targets"]["https://a.example.com/"]["still_open"]), 1)
            self.assertEqual(len(diff["targets"]["https://b.example.com/"]["new"]), 1)

            # 3. SARIF 2.1.0 report
            sarif_path = rm.sarif_report({"id": "curr2"}, targets, {
                "https://a.example.com/": [f_common],
                "https://b.example.com/": [f_new],
            })
            sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"][0]["results"]), 2)
            self.assertGreaterEqual(len(sarif["runs"][0]["tool"]["driver"]["rules"]), 2)

            # 4. AI Package export
            pkg_meta = rm.ai_package_report({"id": "curr2"}, targets, {
                "https://a.example.com/": [f_common],
                "https://b.example.com/": [f_new],
            })
            pkg_dir = Path(pkg_meta["package_dir"])
            self.assertTrue((pkg_dir / "ai_report_validated.json").exists())
            self.assertTrue((pkg_dir / "ai_findings.jsonl").exists())
            self.assertTrue((pkg_dir / "AI_ANALYSIS_PROMPT.md").exists())
            self.assertTrue(list((pkg_dir / "chunks").glob("chunk_*.json")))


class TestProfilesScopeAndDiagnostics(unittest.TestCase):
    def test_profiles_scope_patterns_and_device_diagnostics(self):
        from config import Config, VALID_PROFILES
        from core.diagnostics import collect_device_diagnostics
        from core.scope import ScopeGuard

        # 1. Profiles
        for p in VALID_PROFILES:
            cfg = Config()
            cfg.apply_profile(p)
            self.assertEqual(cfg.validate(), [], f"profile {p} produced invalid config")

        cfg_stealth = Config()
        cfg_stealth.apply_profile("stealth")
        self.assertTrue(cfg_stealth.get("active.safe_mode"))
        self.assertEqual(cfg_stealth.get("scan.concurrency_targets"), 1)

        with self.assertRaises(ValueError):
            Config().apply_profile("nonexistent_profile")

        # 2. Scope include/exclude patterns and discovered subdomain check
        guard = ScopeGuard(
            ["example.com"],
            allow_private=True,
            allow_subdomains=True,
            include_patterns=["/api/*"],
            exclude_patterns=["/api/internal/*", "staging.example.com"],
        )
        self.assertTrue(guard.check_target("https://example.com/api/v1/users").allowed)
        self.assertFalse(guard.check_target("https://example.com/public/index.html").allowed)
        self.assertFalse(guard.check_target("https://example.com/api/internal/debug").allowed)
        self.assertTrue(guard.check_discovered_subdomain("api.example.com", "example.com").allowed)
        self.assertFalse(guard.check_discovered_subdomain("staging.example.com", "example.com").allowed)

        guard_no_sub = ScopeGuard(["example.com"], allow_private=True, allow_subdomains=False)
        self.assertFalse(guard_no_sub.check_discovered_subdomain("sub.example.com", "example.com").allowed)

        # 3. Device diagnostics (local Termux/Android capability check)
        diag = collect_device_diagnostics()
        self.assertIn("environment", diag)
        self.assertIn("memory", diag)
        self.assertIn("storage", diag)
        self.assertIn("compatibility_matrix", diag)
        self.assertGreater(len(diag["compatibility_matrix"]), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)