"""Comprehensive unit test suite for Work Items A..R (>=1 positive and >=1 negative test per module, 0 network)."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import Config
from core.context import ScanContext, Target
from core.finding import (
    CONFIRMED,
    CRITICAL,
    HIGH,
    INFO,
    LOW,
    MEDIUM,
    NEEDS_MANUAL,
    Finding,
    compute_global_score,
    score_breakdown,
    score_counts,
)
from core.http_client import Fetched
from core.report_manager import compute_systemic_findings, split_markdown_chunks
from core.scope import ScopeGuard
from core.tool_runner import (
    parse_arjun_output,
    parse_ffuf_output,
    parse_wafw00f_output,
    strip_ansi,
)
from dns.topology import CF_DNS_ONLY, CF_PROXIED, DIRECT, analyze_topology, is_cloudflare_ip
from modules.cookies import CookieModule, is_httponly_exempt, is_session_like
from modules.dns_security import (
    COMMON_DKIM_SELECTORS,
    canonicalize_subdomain,
    dedupe_subdomains,
    evaluate_caa,
    evaluate_dnssec,
    evaluate_wildcard_dns,
    extract_dmarc_report_domains,
    parse_dmarc_tags,
)
from modules.http_security import HttpSecurityModule, parse_raw_header_lines
from modules.infrastructure import classify_port_severity
from modules.reconnaissance import is_standard_cms_robots_entry
from modules.ssl_tls import SslTlsModule, evaluate_cipher_name
from net.client import fetch, fetch_sync, make_unreachable_finding, should_retry_status
from probe.challenge import detect_challenge, extract_meta_csp
from probe.context import (
    ATTR_DOUBLE,
    COMMENT,
    JS_STRING,
    MARKUP,
    classify,
    evaluate_xss_outcome,
    locate_and_classify,
)
from probe.soft404 import (
    BaselineSample,
    Soft404Baseline,
    body_md5,
    detect_spa_markers,
    evaluate_path_probe,
    is_soft404,
    matches_content_signature,
    normalize_body,
)
from tests.integration.replay import replay_all


class TestAccuracyModules(unittest.IsolatedAsyncioTestCase):
    # ---- Item B: probe/soft404.py (positive & negative) ------------------
    def test_soft404_detection_and_signatures(self) -> None:
        spa_body = (
            '<!DOCTYPE html><html data-capo=""><head><title>Nuxt SPA Shell</title></head>'
            '<body><div id="app">Welcome to the SPA catch-all shell routing page</div>'
            '<script>window.__NUXT__={state:{},config:{}};</script></body></html>'
        )
        norm_md5 = body_md5(spa_body)
        baseline = Soft404Baseline(
            samples=[BaselineSample(path="/rand1234", status=200, length=len(spa_body), md5=norm_md5)],
            calibration="stable",
            is_spa=bool(detect_spa_markers(spa_body)),
        )
        self.assertTrue(baseline.is_spa)
        # Positive soft-404 match
        self.assertTrue(is_soft404(200, spa_body, baseline))
        # Negative soft-404 match (distinct body and status)
        real_env = "APP_KEY=base64:123456\nDB_PASSWORD=secret\n"
        self.assertFalse(is_soft404(200, real_env, baseline))
        self.assertTrue(matches_content_signature("/.env", real_env))
        self.assertFalse(matches_content_signature("/.env", spa_body))

    # ---- Item C: probe/context.py (positive & negative) ------------------
    def test_xss_context_classifier_positive_and_negative(self) -> None:
        # Positive MARKUP + two-payload agreement -> HIGH / CONFIRMED
        markup_html = '<html><body><div>"><bzz123>x</b></div></body></html>'
        ctx1, surv1, _ = locate_and_classify(markup_html, "zz123", "<bzz123>x</b>")
        self.assertEqual(ctx1, MARKUP)
        self.assertTrue(surv1)
        sev, conf = evaluate_xss_outcome(ctx1, surv1, True, markup_html)
        self.assertEqual((sev, conf), (HIGH, CONFIRMED))

        # Without second payload agreement -> MEDIUM / NEEDS MANUAL VERIFICATION
        sev_no2, conf_no2 = evaluate_xss_outcome(ctx1, surv1, False, markup_html)
        self.assertEqual((sev_no2, conf_no2), (MEDIUM, NEEDS_MANUAL))

        # Negative: JS_STRING inside Next.js RSC -> INFO / NEEDS MANUAL VERIFICATION
        rsc_html = '<script>self.__next_f.push([1,"\\u003cbzz123\\u003ex\\u003c/b\\u003e"])</script>'
        ctx_rsc, surv_rsc, _ = locate_and_classify(rsc_html, "zz123", "<bzz123>x</b>")
        self.assertEqual(ctx_rsc, JS_STRING)
        self.assertFalse(surv_rsc)
        self.assertEqual(evaluate_xss_outcome(ctx_rsc, surv_rsc, False, rsc_html), (INFO, NEEDS_MANUAL))

        # Attribute context and comment context
        attr_html = '<input value="hello <bzz123>x</b>">'
        self.assertEqual(classify(attr_html, attr_html.find("<bzz123>")), ATTR_DOUBLE)
        comment_html = "<!-- comment <bzz123>x</b> -->"
        self.assertEqual(classify(comment_html, comment_html.find("<bzz123>")), COMMENT)

    # ---- Item D: net/client.py (positive & negative) ---------------------
    async def test_net_client_retry_and_unreachable(self) -> None:
        # Positive: 2 timeouts then success on 3rd attempt
        calls = 0

        async def _flaky_op(attempt: int):
            nonlocal calls
            calls += 1
            if calls <= 2:
                raise TimeoutError("transient timeout")
            return Fetched("https://example.com/", 200, {"content-length": "2"}, "ok", 5.0)

        res = await fetch(_flaky_op, attempts=3, sleep_fn=lambda _w: asyncio.sleep(0))
        self.assertEqual(res.status, 200)
        self.assertEqual(calls, 3)

        # Negative: 404 is not retried
        self.assertFalse(should_retry_status(404))
        self.assertTrue(should_retry_status(503))

        # 3/3 failure -> TARGET_UNREACHABLE
        f_unreach = make_unreachable_finding("https://dead.example.com/", "timed out")
        self.assertEqual(f_unreach.title, "TARGET_UNREACHABLE")
        self.assertEqual(f_unreach.severity, HIGH)

    # ---- Item E: probe/challenge.py (positive & negative) ----------------
    def test_challenge_detection_positive_and_negative(self) -> None:
        cf_html = '<html><head><title>Just a moment...</title><meta http-equiv="content-security-policy" content="default-src \'none\'"></head><body></body></html>'
        is_c, prov = detect_challenge(403, {"cf-mitigated": "challenge"}, cf_html)
        self.assertTrue(is_c)
        self.assertEqual(prov, "Cloudflare")
        self.assertEqual(extract_meta_csp(cf_html), "default-src 'none'")

        # Negative: normal 403 application response is not a WAF challenge
        normal_403 = "<html><head><title>403 Forbidden - Admin Area</title></head><body>Insufficient role</body></html>"
        is_c2, _ = detect_challenge(403, {"server": "nginx"}, normal_403)
        self.assertFalse(is_c2)

    # ---- Item F: modules/http_security.py (positive & negative) ----------
    async def test_headers_duplicate_and_csp_comma(self) -> None:
        cfg = Config()
        scope = ScopeGuard(["https://example.com/"], allow_private=True)

        # Positive: duplicate XFO & comma-separated CSP
        raw_bad = (
            "X-Frame-Options: DENY\n"
            "X-Frame-Options: SAMEORIGIN\n"
            "Content-Security-Policy: frame-ancestors 'self', upgrade-insecure-requests\n"
            "Strict-Transport-Security: max-age=0\n"
        )
        h_bad, m_bad = parse_raw_header_lines(raw_bad)

        class _StubHttp:
            def __init__(self, hdrs, multi):
                self.hdrs = hdrs
                self.multi = multi

            async def request(self, method, url, **kwargs):
                return Fetched(url, 200, self.hdrs, "<html>ok</html>", 1.0, final_url=url, multi_headers=self.multi)

        ctx_bad = ScanContext(target=Target("https://example.com/"), config=cfg, scope=scope, http=_StubHttp(h_bad, m_bad), stop_event=asyncio.Event(), counter={})
        findings_bad = await HttpSecurityModule({}).run(ctx_bad)
        titles_bad = [f.title for f in findings_bad]
        self.assertIn("Duplicate X-Frame-Options header, value invalid", titles_bad)
        self.assertIn("Malformed Content-Security-Policy (comma-separated directives)", titles_bad)
        self.assertIn("Strict-Transport-Security sets max-age=0 (HSTS disabled)", titles_bad)

        # Negative: clean single-value headers with semicolon-separated CSP
        raw_good = (
            "X-Frame-Options: DENY\n"
            "X-Content-Type-Options: nosniff\n"
            "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
            "Content-Security-Policy: default-src 'self'; frame-ancestors 'self'; upgrade-insecure-requests\n"
            "Referrer-Policy: strict-origin-when-cross-origin\n"
            "Permissions-Policy: geolocation=()\n"
            "Cross-Origin-Opener-Policy: same-origin\n"
        )
        h_good, m_good = parse_raw_header_lines(raw_good)
        ctx_good = ScanContext(target=Target("https://example.com/"), config=cfg, scope=scope, http=_StubHttp(h_good, m_good), stop_event=asyncio.Event(), counter={})
        findings_good = await HttpSecurityModule({}).run(ctx_good)
        dup_or_malformed = [f for f in findings_good if "Duplicate" in f.title or "Malformed" in f.title]
        self.assertEqual(len(dup_or_malformed), 0)

    # ---- Item G: modules/cookies.py (positive & negative) ----------------
    def test_cookie_exemptions_and_prefixes(self) -> None:
        self.assertTrue(is_httponly_exempt("XSRF-TOKEN"))
        self.assertFalse(is_session_like("XSRF-TOKEN"))
        self.assertTrue(is_session_like("laravel_session"))

        cfg = Config()
        scope = ScopeGuard(["https://example.com/"], allow_private=True)
        ctx = ScanContext(target=Target("https://example.com/"), config=cfg, scope=scope, http=None, stop_event=asyncio.Event(), counter={})
        mod = CookieModule()

        # Negative (0 findings): valid CSRF + session cookies
        clean = mod.audit_lines(ctx, [
            "Set-Cookie: XSRF-TOKEN=abc; Path=/; Secure; SameSite=Lax",
            "Set-Cookie: __Host-sid=xyz; Path=/; Secure; HttpOnly; SameSite=Lax",
        ])
        self.assertEqual(len(clean), 0)

        # Positive: broken __Host- prefix (has Domain and missing Secure)
        broken = mod.audit_lines(ctx, [
            "Set-Cookie: __Host-sid=xyz; Domain=example.com; Path=/admin; HttpOnly; SameSite=Lax",
        ])
        self.assertTrue(any("__Host-" in f.title and f.severity == MEDIUM for f in broken))

    # ---- Item H: core/tool_runner.py (positive & negative) ---------------
    def test_tool_parsers_wafw00f_arjun_ffuf(self) -> None:
        self.assertEqual(strip_ansi("\x1b[1;91mHello\x1b[0m"), "Hello")
        # Positive wafw00f hit
        w_pos = parse_wafw00f_output("\x1b[1;92m[+] The site https://a.com is behind Cloudflare WAF.\x1b[0m", "https://a.com/")
        self.assertEqual(len(w_pos), 1)
        self.assertIn("WAF detected", w_pos[0].title)
        # Positive arjun hit vs Negative progress line
        a_pos = parse_arjun_output("[!] Progress: 50%\n[+] Parameter found: debug_id\n", "https://a.com/")
        self.assertEqual(len(a_pos), 1)
        # Positive ffuf JSON results[] with seen_paths deduplication
        seen = {"/already-seen"}
        ffuf_json = '{"commandline": "ffuf -w /tmp/w", "results": [{"url": "https://a.com/already-seen", "status": 200, "length": 10, "words": 2}, {"url": "https://a.com/secret-api", "status": 200, "length": 42, "words": 5}]}'
        f_out = parse_ffuf_output(ffuf_json, "https://a.com/", seen_paths=seen)
        self.assertEqual(len(f_out), 1)
        self.assertEqual(f_out[0].title, "/secret-api [200]")
        self.assertNotIn("/tmp/w", f_out[0].evidence)

    # ---- Item I, L, M, N, O, Q: DNS & Topology (positive & negative) -----
    def test_dns_subdomains_topology_dnssec_and_anomalies(self) -> None:
        # Item I: canonicalize & dedupe
        self.assertEqual(canonicalize_subdomain("www.admin.Example.COM.", "example.com"), "admin.example.com")
        self.assertEqual(canonicalize_subdomain("mail.mail.example.com", "example.com"), "mail.example.com")
        ded = dedupe_subdomains([("www.admin.example.com", ["1.2.3.4"]), ("admin.example.com.", ["1.2.3.4"])], apex="example.com")
        self.assertEqual(len(ded), 1)

        # Item L: CF_PROXIED vs CF_DNS_ONLY vs DIRECT
        self.assertTrue(is_cloudflare_ip("104.21.55.146"))
        self.assertFalse(is_cloudflare_ip("145.223.86.178"))
        t_prox = analyze_topology(["ada.ns.cloudflare.com"], ["104.21.55.146"])
        self.assertEqual(t_prox.classification, CF_PROXIED)
        self.assertEqual(len(t_prox.findings), 0)
        t_grey = analyze_topology(["ada.ns.cloudflare.com"], ["145.223.86.178"])
        self.assertEqual(t_grey.classification, CF_DNS_ONLY)
        self.assertEqual(t_grey.scan_target, "145.223.86.178")
        t_dir = analyze_topology(["ns1.hostinger.com"], ["145.223.86.178"])
        self.assertEqual(t_dir.classification, DIRECT)

        # Item M: Wildcard DNS positive & negative
        wc_yes, bf_yes, _, _ = evaluate_wildcard_dns(["1.1.1.1"], ["1.1.1.1"])
        self.assertTrue(wc_yes)
        self.assertFalse(bf_yes)
        wc_no, bf_no, _, _ = evaluate_wildcard_dns([], [])
        self.assertFalse(wc_no)
        self.assertTrue(bf_no)

        # Item N: DMARC tags & report domains
        d_tags = parse_dmarc_tags("v=DMARC1; p=quarantine; pct=50; sp=none; rua=mailto:agg@dmarc.brevo.com")
        self.assertEqual(d_tags["p"], "quarantine")
        self.assertEqual(d_tags["pct"], "50")
        self.assertEqual(extract_dmarc_report_domains(d_tags["rua"]), ["dmarc.brevo.com"])

        # Item O: DNSSEC states (island of trust, broken delegation, not enabled)
        f_island = evaluate_dnssec(["257 3 13 abc"], [])
        self.assertEqual(len(f_island), 1)
        self.assertEqual(f_island[0].severity, MEDIUM)
        f_broken = evaluate_dnssec([], ["12345 13 2 deadbeef"])
        self.assertEqual(f_broken[0].severity, HIGH)
        f_off = evaluate_dnssec([], [])
        self.assertEqual(f_off[0].severity, LOW)

        # Item Q: 16 DKIM selectors
        self.assertGreaterEqual(len(COMMON_DKIM_SELECTORS), 16)
        self.assertIn("brevo", COMMON_DKIM_SELECTORS)
        self.assertIn("hostinger", COMMON_DKIM_SELECTORS)

    # ---- Item J, K, P: Scoring, Reports, TLS, Ports, Robots --------------
    def test_scoring_caps_reports_tls_and_robots(self) -> None:
        # J1: Grade cap with CRITICAL -> max B; HIGH -> max A-
        sc_crit, gr_crit = score_counts({"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})
        self.assertNotIn(gr_crit, ("A", "A-"))
        sc_high, gr_high = score_counts({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0})
        self.assertEqual(gr_high, "A-")
        # J2: Global score uses min when CRITICAL exists, else mean
        g_score, g_grade = compute_global_score([96, 94, 72], has_critical=True)
        self.assertEqual(g_score, 72)
        self.assertEqual(g_grade, "C")
        g_mean, _ = compute_global_score([90, 100], has_critical=False)
        self.assertEqual(g_mean, 95)
        self.assertEqual(len(score_breakdown({"CRITICAL": 1})), 5)

        # J4: Cloudflare edge ports vs origin ports
        self.assertEqual(classify_port_severity(8080, topology="CF_PROXIED"), (INFO, "edge port"))
        self.assertEqual(classify_port_severity(8080, topology="CF_DNS_ONLY")[0], LOW)

        # J5: Standard WordPress robots.txt entries
        self.assertTrue(is_standard_cms_robots_entry("/wp-admin/"))
        self.assertFalse(is_standard_cms_robots_entry("/secret-backup/"))

        # K1: Split markdown without mid-finding truncation
        big_md = "# Header\n" + "\n### [LOW] Finding\nBody text\n" * 5000
        chunks = split_markdown_chunks(big_md, max_chars=100_000)
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(len(c) <= 100_000 for c in chunks))

        # K3: Finding JSON fields
        f = Finding(target="https://a.com/", category="Test", title="T", severity="MEDIUM", description="D")
        ai_d = f.to_ai_dict()
        for req_key in ("schema_version", "confidence", "cwe", "cvss", "evidence_hash", "first_seen", "last_seen", "edge", "check_outcome"):
            self.assertIn(req_key, ai_d)

        # P2, P3, P6: Cipher evaluation, CAA evaluation & systemic findings
        self.assertEqual(evaluate_cipher_name("TLS_RSA_WITH_RC4_128_SHA", "TLSv1.2")[0].severity, MEDIUM)
        self.assertEqual(evaluate_cipher_name("ECDHE-RSA-AES128-SHA", "TLSv1.2")[0].severity, LOW)
        self.assertEqual( len(evaluate_cipher_name("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2")), 0 )
        self.assertEqual(evaluate_caa([])[0].severity, LOW)
        self.assertEqual(evaluate_caa(['0 issue "*"'])[0].severity, MEDIUM)

        sys_f = compute_systemic_findings({
            "https://h1.com": [{"title": "Deprecated TLS protocol supported (TLSv1.0)"}, {"title": "No CAA record restricts certificate issuance"}],
            "https://h2.com": [{"title": "Deprecated TLS protocol supported (TLSv1.1)"}, {"title": "No CAA record restricts certificate issuance"}],
            "https://h3.com": [{"title": "Deprecated TLS protocol supported (TLSv1.0)"}, {"title": "No CAA record restricts certificate issuance"}],
        })
        self.assertEqual(len(sys_f), 2)

    # ---- Item R4: Integration Replay of all 15 fixtures ------------------
    async def test_integration_replay_all_15_fixtures(self) -> None:
        summary = await replay_all()
        self.assertEqual(summary["nuxt_spa.html"]["critical"], 0)
        self.assertEqual(summary["next_rsc.html"]["context"], "JS_STRING")
        self.assertEqual(summary["next_rsc.html"]["severity"], "INFO")
        self.assertEqual(summary["cf_challenge.html"]["app_header_findings"], 0)
        self.assertEqual(summary["cf_challenge.html"]["csp_source"], "meta")
        self.assertEqual(summary["dup_headers.txt"]["xfo_duplicate_medium"], 1)
        self.assertEqual(summary["dup_headers.txt"]["missing_xfo"], 0)
        self.assertEqual(summary["wafw00f_banner.txt"]["findings"], 1)
        self.assertEqual(summary["wafw00f_banner.txt"]["esc_bytes"], 0)
        self.assertEqual(summary["arjun_progress.txt"]["params"], 0)
        self.assertEqual(summary["ffdiamondbd_cookies.txt"]["findings"], 0)
        self.assertEqual(summary["codmshopbd_cookies.txt"]["findings"], 0)
        self.assertEqual(summary["dns_grey_cloud.json"]["origin_exposed_medium"], 1)
        self.assertEqual(summary["dns_grey_cloud.json"]["scan_target"], "145.223.86.178")
        self.assertEqual(summary["dns_wildcard.json"]["wildcard_dns"], True)
        self.assertEqual(summary["dns_wildcard.json"]["brute_force_enabled"], False)
        self.assertEqual(summary["dns_island_dnssec.json"]["findings"], 1)
        self.assertEqual(summary["dns_island_dnssec.json"]["severity"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
