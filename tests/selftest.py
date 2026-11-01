#!/usr/bin/env python3
"""Install-time smoke test."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

CHECKS = []


def check(name):
    def wrap(fn):
        CHECKS.append((name, fn))
        return fn
    return wrap


@check("config loads and validates")
def _c():
    import config
    c = config.load()
    assert not c.validate(), c.validate()


@check("validator normalizes and rejects")
def _v():
    from core.validator import validate
    assert validate("example.com").normalized == "https://example.com/"
    assert not validate("ftp://x").valid
    assert not validate("http://bad host").valid


@check("scope blocks private IPs by default")
def _s():
    from core.scope import ScopeGuard
    g = ScopeGuard(["localhost"], allow_private=False)
    assert not g.check_target("http://127.0.0.1/").allowed
    g2 = ScopeGuard([], allow_private=True)
    assert g2.check_target("http://127.0.0.1/").allowed


@check("finding ids and confidence coercion")
def _f():
    from core.finding import Finding
    f = Finding(target="https://a/", category="X", title="t", severity="BOGUS",
                description="d", confidence="nope")
    assert f.severity == "INFO" and f.finding_id.startswith("TSMSS-")


@check("database roundtrip")
def _d():
    import tempfile
    from core.database import Database
    from core.finding import Finding
    with tempfile.TemporaryDirectory() as d:
        db = Database(Path(d) / "t.db")
        sid = db.create_scan({}, 1)
        db.add_targets(sid, ["https://a/"])
        db.add_findings(sid, [Finding(target="https://a/", category="X", title="t",
                                      severity="LOW", description="d")])
        assert len(db.findings(sid)) == 1
        db.close()


@check("modules import and expose run()")
def _m():
    from core.engine import build_modules
    mods = build_modules({})
    assert len(mods) >= 13
    assert all(callable(m.run) for m in mods)


@check("report template substitutes cleanly")
def _r():
    import tempfile
    from core.report_manager import ReportManager
    base = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory() as d:
        rm = ReportManager(Path(d), base / "templates" / "report.html")
        out = rm.html_report({"id": "x"}, [{"url": "https://a/", "status": "done"}],
                             {"https://a/": []})
        assert out.exists() and "TSMSS" in out.read_text()


def main() -> int:
    failed = 0
    for name, fn in CHECKS:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
    print(f"{len(CHECKS) - failed}/{len(CHECKS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())