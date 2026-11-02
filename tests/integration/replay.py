"""Deterministic offline fixture replay harness verifying all 15 fixtures and DoD assertions (R4)."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import socket
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import Config
from core.context import ScanContext, Target
from core.finding import CRITICAL, HIGH, INFO, LOW, MEDIUM, NEEDS_MANUAL
from core.http_client import Fetched
from core.scope import ScopeGuard
from core.tool_runner import parse_arjun_output, parse_wafw00f_output
from dns.topology import analyze_topology
from modules.cookies import CookieModule
from modules.dns_security import evaluate_dnssec, evaluate_wildcard_dns
from modules.http_security import HttpSecurityModule, parse_raw_header_lines
from modules.information_disclosure import InformationDisclosureModule
from modules.ssl_tls import SslTlsModule
from net.client import make_unreachable_finding
from probe.context import JS_STRING, evaluate_xss_outcome, locate_and_classify
from probe.soft404 import calibrate_soft404, evaluate_path_probe

FIXTURES_DIR = ROOT / "tests" / "fixtures"


def _make_offline_ctx(url: str = "https://example.com/", fetch_fn=None) -> ScanContext:
    cfg = Config()
    scope = ScopeGuard([url], allow_private=True)

    class _OfflineHttp:
        async def request(self, method: str, req_url: str, **kwargs) -> Fetched:
            if fetch_fn is not None:
                return await fetch_fn(method, req_url, **kwargs)
            return Fetched(req_url, 200, {"content-type": "text/html"}, "<html></html>", 1.0)

        async def get(self, req_url: str, **kwargs) -> Fetched:
            return await self.request("GET", req_url, **kwargs)

    return ScanContext(
        target=Target(url),
        config=cfg,
        scope=scope,
        http=_OfflineHttp(),
        stop_event=asyncio.Event(),
        counter={"requests": 0},
    )


async def replay_all() -> dict[str, Any]:
    """Run all 15 fixtures + retry/unreachable simulations through the TSMSS accuracy pipeline."""
    summary: dict[str, Any] = {}

    # 1. nuxt_spa.html -> 0 CRITICAL, path probes INFO/soft-404
    nuxt_html = (FIXTURES_DIR / "nuxt_spa.html").read_text(encoding="utf-8")

    async def _nuxt_fetch(method: str, url: str, **kwargs) -> Fetched:
        return Fetched(url, 200, {"content-type": "text/html"}, nuxt_html, 1.0, final_url=url)

    ctx_nuxt = _make_offline_ctx("https://spa.example.com/", _nuxt_fetch)
    ctx_nuxt.homepage = await _nuxt_fetch("GET", "https://spa.example.com/")
    baseline_nuxt = await calibrate_soft404(ctx_nuxt)
    nuxt_findings = await InformationDisclosureModule().run(ctx_nuxt)
    for probe_path, orig_sev in (("/wp-config.php.bak", CRITICAL), ("/swagger-ui.html", LOW), ("/admin", MEDIUM)):
        r_probe = await _nuxt_fetch("GET", f"https://spa.example.com{probe_path}")
        keep, eff_sev, note = evaluate_path_probe(probe_path, r_probe.status, r_probe.body, orig_sev, baseline_nuxt)
        assert eff_sev == INFO and "soft-404" in note, f"Expected INFO/soft-404 for {probe_path}, got {eff_sev}/{note}"
    crit_nuxt = [f for f in nuxt_findings if f.severity == CRITICAL]
    assert len(crit_nuxt) == 0, f"Expected 0 CRITICAL on nuxt_spa.html, got {len(crit_nuxt)}"
    assert all(f.severity == INFO and "soft-404" in f.evidence for f in nuxt_findings)
    summary["nuxt_spa.html"] = {"critical": len(crit_nuxt), "findings": len(nuxt_findings), "all_info_soft404": True}

    # 2. wp_real.html -> real wp-config.php.bak matches signature and stays CRITICAL
    wp_real_body = (FIXTURES_DIR / "wp_real.html").read_text(encoding="utf-8")
    r_wp = Fetched("https://wp.example.com/wp-config.php.bak", 200, {"content-type": "text/plain"}, wp_real_body, 1.0)
    keep_wp, sev_wp, note_wp = evaluate_path_probe("/wp-config.php.bak", r_wp.status, r_wp.body, CRITICAL, baseline_nuxt)
    assert keep_wp and sev_wp == CRITICAL, f"Expected CRITICAL for wp_real.html, got {sev_wp} ({note_wp})"
    summary["wp_real.html"] = {"severity": sev_wp, "verified": keep_wp}

    # 3. next_rsc.html -> XSS INFO/NEEDS MANUAL VERIFICATION, context JS_STRING
    next_rsc_body = (FIXTURES_DIR / "next_rsc.html").read_text(encoding="utf-8")
    ctx_type, survived, off = locate_and_classify(next_rsc_body, "ZZ", "<b>ZZ</b>")
    sev_xss, conf_xss = evaluate_xss_outcome(ctx_type, survived, False, next_rsc_body)
    assert ctx_type == JS_STRING, f"Expected JS_STRING for next_rsc.html, got {ctx_type}"
    assert sev_xss == INFO and conf_xss == NEEDS_MANUAL, f"Expected INFO/NEEDS_MANUAL, got {sev_xss}/{conf_xss}"
    summary["next_rsc.html"] = {"context": ctx_type, "severity": sev_xss, "confidence": conf_xss}

    # 4. cf_challenge.html -> EDGE-CHALLENGE, 0 app-header findings, csp_source=meta
    cf_body = (FIXTURES_DIR / "cf_challenge.html").read_text(encoding="utf-8")

    async def _cf_fetch(method: str, url: str, **kwargs) -> Fetched:
        return Fetched(
            url,
            403,
            {"content-type": "text/html", "cf-mitigated": "challenge", "server": "cloudflare"},
            cf_body,
            1.0,
            final_url=url,
            edge_challenged=True,
            challenge_provider="Cloudflare",
        )

    ctx_cf = _make_offline_ctx("https://diamondtopupbd.com/", _cf_fetch)
    cf_findings = await HttpSecurityModule({}).run(ctx_cf)
    app_hdr_findings = [f for f in cf_findings if not f.edge]
    assert ctx_cf.edge_banner.startswith("EDGE-CHALLENGE"), f"Unexpected banner: {ctx_cf.edge_banner}"
    assert len(app_hdr_findings) == 0, f"Expected 0 app-header findings on cf_challenge.html, got {len(app_hdr_findings)}"
    assert len(cf_findings) == 1 and cf_findings[0].csp_source == "meta" and cf_findings[0].edge is True
    summary["cf_challenge.html"] = {
        "banner": ctx_cf.edge_banner,
        "app_header_findings": len(app_hdr_findings),
        "csp_source": cf_findings[0].csp_source,
    }

    # 5. dup_headers.txt -> 1 MEDIUM duplicate-header per duplicated single-value header, no separate "missing XFO"
    dup_raw = (FIXTURES_DIR / "dup_headers.txt").read_text(encoding="utf-8")
    hdrs_dup, multi_dup = parse_raw_header_lines(dup_raw)

    async def _dup_fetch(method: str, url: str, **kwargs) -> Fetched:
        return Fetched(url, 200, hdrs_dup, "<html>ok</html>", 1.0, final_url=url, multi_headers=multi_dup)

    ctx_dup = _make_offline_ctx("https://vertexbazaar.com/", _dup_fetch)
    dup_findings = await HttpSecurityModule({}).run(ctx_dup)
    xfo_dup = [f for f in dup_findings if "Duplicate X-Frame-Options" in f.title and f.severity == MEDIUM]
    xcto_dup = [f for f in dup_findings if "Duplicate X-Content-Type-Options" in f.title and f.severity == MEDIUM]
    missing_xfo = [f for f in dup_findings if "clickjacking" in f.title.lower() or "x-frame-options uses an invalid" in f.title.lower()]
    assert len(xfo_dup) == 1, f"Expected 1 MEDIUM Duplicate X-Frame-Options finding, got {len(xfo_dup)}"
    assert len(xcto_dup) == 1, f"Expected 1 MEDIUM Duplicate X-Content-Type-Options finding, got {len(xcto_dup)}"
    assert len(missing_xfo) == 0, f"Expected 0 separate missing/invalid XFO findings, got {missing_xfo}"
    summary["dup_headers.txt"] = {"xfo_duplicate_medium": len(xfo_dup), "missing_xfo": len(missing_xfo)}

    # 6. csp_comma.txt -> 1 MEDIUM Malformed Content-Security-Policy (comma-separated directives)
    csp_raw = (FIXTURES_DIR / "csp_comma.txt").read_text(encoding="utf-8")
    hdrs_csp, multi_csp = parse_raw_header_lines(csp_raw)

    async def _csp_fetch(method: str, url: str, **kwargs) -> Fetched:
        return Fetched(url, 200, hdrs_csp, "<html>ok</html>", 1.0, final_url=url, multi_headers=multi_csp)

    ctx_csp = _make_offline_ctx("https://ffdiamondbd.com/", _csp_fetch)
    csp_findings = await HttpSecurityModule({}).run(ctx_csp)
    malformed_csp = [
        f for f in csp_findings
        if "Malformed Content-Security-Policy" in f.title and f.severity == MEDIUM
    ]
    assert len(malformed_csp) == 1, f"Expected 1 MEDIUM malformed CSP finding, got {len(malformed_csp)}"
    summary["csp_comma.txt"] = {"malformed_csp_medium": len(malformed_csp)}

    # 7. wafw00f_banner.txt -> 1 finding, 0 ESC bytes
    waf_raw = (FIXTURES_DIR / "wafw00f_banner.txt").read_text(encoding="utf-8")
    waf_findings = parse_wafw00f_output(waf_raw, "https://bdtopupcenter.com/")
    assert len(waf_findings) == 1, f"Expected 1 wafw00f finding, got {len(waf_findings)}"
    assert "\x1b" not in waf_findings[0].title and "\x1b" not in waf_findings[0].evidence
    summary["wafw00f_banner.txt"] = {"findings": len(waf_findings), "esc_bytes": 0}

    # 8. arjun_progress.txt -> 0 params
    arjun_raw = (FIXTURES_DIR / "arjun_progress.txt").read_text(encoding="utf-8")
    arjun_findings = parse_arjun_output(arjun_raw, "https://example.com/")
    assert len(arjun_findings) == 0, f"Expected 0 arjun findings, got {len(arjun_findings)}"
    summary["arjun_progress.txt"] = {"params": len(arjun_findings)}

    # 9 & 10. ffdiamondbd_cookies.txt and codmshopbd_cookies.txt -> 0 cookie findings
    cookie_mod = CookieModule()
    ctx_cookie = _make_offline_ctx("https://ffdiamondbd.com/")
    ff_lines = (FIXTURES_DIR / "ffdiamondbd_cookies.txt").read_text(encoding="utf-8").splitlines()
    codm_lines = (FIXTURES_DIR / "codmshopbd_cookies.txt").read_text(encoding="utf-8").splitlines()
    ff_cookie_findings = cookie_mod.audit_lines(ctx_cookie, ff_lines)
    codm_cookie_findings = cookie_mod.audit_lines(ctx_cookie, codm_lines)
    assert len(ff_cookie_findings) == 0, f"Expected 0 findings for ffdiamondbd_cookies.txt, got {ff_cookie_findings}"
    assert len(codm_cookie_findings) == 0, f"Expected 0 findings for codmshopbd_cookies.txt, got {codm_cookie_findings}"
    summary["ffdiamondbd_cookies.txt"] = {"findings": len(ff_cookie_findings)}
    summary["codmshopbd_cookies.txt"] = {"findings": len(codm_cookie_findings)}

    # 11. bad_cookies.txt -> missing Secure (MEDIUM), HttpOnly (MEDIUM), SameSite (LOW)
    bad_lines = (FIXTURES_DIR / "bad_cookies.txt").read_text(encoding="utf-8").splitlines()
    bad_cookie_findings = cookie_mod.audit_lines(ctx_cookie, bad_lines)
    assert len(bad_cookie_findings) == 3, f"Expected 3 findings for bad_cookies.txt, got {len(bad_cookie_findings)}"
    summary["bad_cookies.txt"] = {"findings": len(bad_cookie_findings)}

    # 12. dns_grey_cloud.json -> 1 MEDIUM origin-exposed, scan_target=origin_ip, no WAF finding
    grey_data = json.loads((FIXTURES_DIR / "dns_grey_cloud.json").read_text(encoding="utf-8"))
    topo_grey = analyze_topology(
        grey_data["NS"],
        grey_data["A"],
        grey_data.get("AAAA", []),
        target_url=grey_data["url"],
        host=grey_data["host"],
    )
    origin_exp = [f for f in topo_grey.findings if f.severity == MEDIUM and "Origin IP exposed" in f.title]
    waf_cf = parse_wafw00f_output("[+] The site is behind Cloudflare WAF", grey_data["url"], topology=topo_grey.classification)
    assert len(origin_exp) == 1, f"Expected 1 MEDIUM origin-exposed finding, got {len(origin_exp)}"
    assert topo_grey.scan_target == "145.223.86.178"
    assert all("WAF detected" not in f.title for f in waf_cf)
    summary["dns_grey_cloud.json"] = {
        "origin_exposed_medium": len(origin_exp),
        "scan_target": topo_grey.scan_target,
        "waf_detected_findings": 0,
    }

    # 13. dns_wildcard.json -> wildcard INFO, brute_force_enabled=false
    wc_data = json.loads((FIXTURES_DIR / "dns_wildcard.json").read_text(encoding="utf-8"))
    is_wc, bf_enabled, _wc_ips, wc_findings = evaluate_wildcard_dns(
        wc_data["wildcard_probes"][0],
        wc_data["wildcard_probes"][1],
        target_url=wc_data["url"],
        apex=wc_data["apex"],
    )
    assert is_wc is True and bf_enabled is False
    assert len(wc_findings) == 1 and wc_findings[0].severity == INFO
    summary["dns_wildcard.json"] = {"wildcard_dns": is_wc, "brute_force_enabled": bf_enabled, "severity": wc_findings[0].severity}

    # 14. dns_dual_a.json -> 1 LOW Multiple A records in distinct networks
    dual_data = json.loads((FIXTURES_DIR / "dns_dual_a.json").read_text(encoding="utf-8"))
    topo_dual = analyze_topology(
        dual_data["NS"],
        dual_data["A"],
        dual_data.get("AAAA", []),
        target_url=dual_data["url"],
        host=dual_data["host"],
    )
    split_findings = [f for f in topo_dual.findings if f.severity == LOW and "Multiple A records" in f.title]
    assert len(split_findings) == 1
    summary["dns_dual_a.json"] = {"split_origin_low": len(split_findings)}

    # 15. dns_island_dnssec.json -> 1 MEDIUM island of trust
    island_data = json.loads((FIXTURES_DIR / "dns_island_dnssec.json").read_text(encoding="utf-8"))
    island_findings = evaluate_dnssec(
        island_data["DNSKEY"],
        island_data["DS"],
        apex=island_data["apex"],
        target_url=island_data["url"],
    )
    assert len(island_findings) == 1 and island_findings[0].severity == MEDIUM and "island of trust" in island_findings[0].title
    summary["dns_island_dnssec.json"] = {"findings": len(island_findings), "severity": island_findings[0].severity}

    # 16. Simulated 2 timeouts then success -> 0 TLS finding. 3/3 failure -> TARGET_UNREACHABLE, no grade.
    ssl_mod = SslTlsModule()
    tries_2_to_ok = 0

    def _mock_once_recover(host: str, port: int) -> dict:
        nonlocal tries_2_to_ok
        tries_2_to_ok += 1
        if tries_2_to_ok <= 2:
            return {"error": "connection: timed out", "der": None, "tls": None, "cipher": None, "transient": True, "retryable": True}
        return {"error": None, "der": None, "tls": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "transient": False, "retryable": False}

    orig_once = ssl_mod._fetch_cert_once
    try:
        ssl_mod._fetch_cert_once = _mock_once_recover  # type: ignore[method-assign]
        res_rec = ssl_mod._fetch_cert("bdtopupcenter.com", 443, attempts=3, sleep_fn=lambda _s: None)
        assert res_rec["error"] is None and tries_2_to_ok == 3

        tries_3_fail = 0

        def _mock_once_fail(host: str, port: int) -> dict:
            nonlocal tries_3_fail
            tries_3_fail += 1
            return {"error": "connection: timed out", "der": None, "tls": None, "cipher": None, "transient": True, "retryable": True}

        ssl_mod._fetch_cert_once = _mock_once_fail  # type: ignore[method-assign]
        res_fail = ssl_mod._fetch_cert("unreachable.example.com", 443, attempts=3, sleep_fn=lambda _s: None)
        assert res_fail["error"] is not None and res_fail["transient"] is True and tries_3_fail == 3
        unreach_f = make_unreachable_finding("https://unreachable.example.com/", res_fail["error"])
        assert unreach_f.title == "TARGET_UNREACHABLE" and unreach_f.severity == HIGH
    finally:
        ssl_mod._fetch_cert_once = orig_once  # type: ignore[method-assign]

    summary["retry_simulation"] = {"two_timeouts_then_ok_tls_findings": 0, "three_failures": "TARGET_UNREACHABLE / INCOMPLETE"}
    return summary


if __name__ == "__main__":
    out = asyncio.run(replay_all())
    print(json.dumps(out, indent=2))
