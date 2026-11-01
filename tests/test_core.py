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


if __name__ == "__main__":
    unittest.main(verbosity=2)