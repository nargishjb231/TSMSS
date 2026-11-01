"""Tool registry and adapter tests. No network, no real binaries."""
import sys, unittest
from pathlib import Path
from unittest.mock import patch
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

    @patch("core.tool_runner.shutil.which", return_value="/usr/bin/fake")
    def test_only_query_filtered_without_query(self, _mock_which):
        cfg = Config()
        plain = ToolRunner(cfg, Target("https://example.com/page"), None)
        self.assertFalse([s for s in plain.select() if s.only_query])
        with_query = ToolRunner(cfg, Target("https://example.com/page?id=1"), None)
        self.assertTrue([s for s in with_query.select() if s.only_query])
        plain.cleanup()
        with_query.cleanup()

    @patch("core.tool_runner.shutil.which", return_value="/usr/bin/fake")
    def test_deny_list(self, _mock_which):
        cfg = Config()
        cfg.set("tools.disabled", ["nuclei"])
        r = ToolRunner(cfg, Target("https://example.com/?id=1"), None)
        selected = [s.id for s in r.select()]
        self.assertNotIn("nuclei", selected)
        self.assertGreater(len(selected), 0)
        r.cleanup()

    @patch("core.tool_runner.shutil.which", return_value="/usr/bin/fake")
    def test_allow_list(self, _mock_which):
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
