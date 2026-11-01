#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
bad(){ printf '%s FAIL %s%s\n' "$R" "$N" "$*"; }
FAILED=0

echo "=== 1. wiring audit ==="
grep -q '"external_tools"' core/engine.py && ok "module registered" \
  || { bad "module NOT registered"; FAILED=$((FAILED+1)); }
grep -q "evidence=evidence" core/engine.py && ok "ctx.evidence wired" \
  || bad "ctx.evidence NOT wired"
grep -q "self.evidence = evidence" core/engine.py && ok "engine holds evidence" \
  || bad "engine does not hold evidence"

echo "=== 2. register module if missing ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("core/engine.py")
s = p.read_text()
changed = False
if '"external_tools"' not in s:
    if '"vulnerability_indicators", "infrastructure",' not in s:
        print("  MISS MODULE_ORDER anchor"); sys.exit(1)
    s = s.replace('"vulnerability_indicators", "infrastructure",',
                  '"vulnerability_indicators", "infrastructure", "external_tools",', 1)
    changed = True
if '"external_tools": external_tools.ExternalToolsModule' not in s:
    s = s.replace('"infrastructure": infrastructure.InfrastructureModule,',
                  '"infrastructure": infrastructure.InfrastructureModule,\n'
                  '        "external_tools": external_tools.ExternalToolsModule,', 1)
    changed = True
if "external_tools, information_disclosure" not in s:
    s = s.replace("information_disclosure, infrastructure, ssl_tls,",
                  "external_tools, information_disclosure, infrastructure, ssl_tls,", 1)
    changed = True
if "self.evidence = evidence" not in s:
    s = s.replace("def __init__(self, config, rules: dict, scope, make_http):",
                  "def __init__(self, config, rules: dict, scope, make_http, evidence=None):", 1)
    s = s.replace("        self.make_http = make_http",
                  "        self.make_http = make_http\n        self.evidence = evidence", 1)
    changed = True
if "evidence=self.evidence" not in s:
    s = s.replace("http=http, stop_event=stop_event, counter=counter)",
                  "http=http, stop_event=stop_event, counter=counter,\n"
                  "                              evidence=self.evidence)", 1)
    changed = True
p.write_text(s)
print("  ok   engine wiring complete" if changed else "  skip engine wiring")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 3. main.py passes evidence to the engine ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("main.py")
s = p.read_text()
if "make_http_factory(config, scope, limiter), evidence)" in s:
    print("  skip main.py (already applied)")
else:
    old = """    engine = TargetEngine(config, cfgmod.load_rules(), scope,
                          make_http_factory(config, scope, limiter))"""
    new = """    engine = TargetEngine(config, cfgmod.load_rules(), scope,
                          make_http_factory(config, scope, limiter), evidence)"""
    if old not in s:
        print("  MISS main.py anchor"); sys.exit(1)
    p.write_text(s.replace(old, new, 1))
    print("  ok   evidence passed")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 4. ToolSpec.only_query ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("core/tool_runner.py")
s = p.read_text()
if "only_query: bool = False" in s:
    print("  skip tool_runner (already applied)")
else:
    old = "    needs_wordlist: bool = False\n    needs_dir: bool = False"
    new = "    needs_wordlist: bool = False\n    needs_dir: bool = False\n    only_query: bool = False"
    if old not in s:
        print("  MISS ToolSpec anchor"); sys.exit(1)
    s = s.replace(old, new, 1)

    old_sel = """            if spec.id in self.deny:
                continue
            ok, reason = usable(spec, self.config)"""
    new_sel = """            if spec.id in self.deny:
                continue
            if spec.only_query and "?" not in self.target.url:
                continue
            ok, reason = usable(spec, self.config)"""
    if old_sel not in s:
        print("  MISS select anchor"); sys.exit(1)
    s = s.replace(old_sel, new_sel, 1)
    p.write_text(s)
    print("  ok   only_query honoured")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 5. registry test ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("tests/test_tools.py")
if p.exists() and "test_only_query_filtered" in p.read_text():
    print("  skip test file")
    sys.exit(0)
p.write_text('''"""Tool registry and adapter tests. No network, no real binaries."""
import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import Config
from core.context import Target
from core.tool_runner import ToolRunner, load_registry


class TestRegistry(unittest.TestCase):
    def test_registry_parses_completely(self):
        specs = load_registry()
        self.assertGreaterEqual(len(specs), 15)
        for spec in specs:
            self.assertTrue(spec.id and spec.bin and spec.args, spec.id)
            self.assertIn(spec.output, ("jsonl", "json", "lines"))

    def test_only_query_filtered_without_query(self):
        cfg = Config()
        plain = ToolRunner(cfg, Target("https://example.com/page"), None)
        self.assertFalse([s for s in plain.select() if s.only_query])
        plain.cleanup()

    def test_deny_list(self):
        cfg = Config()
        cfg.set("tools.disabled", ["nuclei"])
        r = ToolRunner(cfg, Target("https://example.com/?id=1"), None)
        self.assertNotIn("nuclei", [s.id for s in r.select()])
        r.cleanup()

    def test_allow_list(self):
        cfg = Config()
        cfg.set("tools.enabled", ["nuclei"])
        r = ToolRunner(cfg, Target("https://example.com/"), None)
        self.assertEqual([s.id for s in r.select()], ["nuclei"])
        r.cleanup()

    def test_parse_jsonl(self):
        from core.tool_runner import ToolSpec
        spec = ToolSpec(id="x", bin="true", category="c", install="go", pkg="p",
                        output="jsonl", args=[], confidence="CONFIRMED",
                        map={"title": "info.name", "severity": "info.severity",
                             "url": "matched-at"})
        r = ToolRunner(Config(), Target("https://e.com/"), None)
        rows = r._parse(spec, '{"info":{"name":"CVE thing","severity":"high"},'
                              '"matched-at":"https://e.com/x"}')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].severity, "HIGH")
        self.assertEqual(rows[0].url, "https://e.com/x")
        r.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
''')
print("  ok   test file written")
PYEOF

echo "=== 6. compile + full tests ==="
python -m compileall -q core modules ui main.py config.py 2>&1 | tail -5
python tests/selftest.py || { bad selftest; FAILED=$((FAILED+1)); }
python -m unittest discover tests 2>&1 | grep -E '^(FAIL|ERROR|OK|Ran |FAILED)' || true
python -m unittest discover tests >/dev/null 2>&1 || { bad "unit tests"; FAILED=$((FAILED+1)); }

echo "=== 7. registry count ==="
python -c "import sys;sys.path.insert(0,'.');from core.tool_runner import load_registry;r=load_registry();print(len(r),'tools,',sum(1 for t in r if t.only_query),'query-only')"

echo
if [ "$FAILED" -eq 0 ]; then printf '%sAll green.%s\n' "$G" "$N"
else printf '%s%d issue(s).%s\n' "$R" "$FAILED" "$N"; exit 1; fi
