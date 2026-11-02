"""Unit tests for Work Item A: Termux temp-dir hardening and 0-byte body guard."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import paths


class TestTempDir(unittest.TestCase):
    def test_startup_probe_succeeds_in_valid_tempdir(self) -> None:
        resolved = paths.startup_probe()
        self.assertTrue(resolved.exists())
        self.assertTrue(resolved.is_dir())

    def test_tmpfile_and_tmpdir_create_inside_writable_dir(self) -> None:
        f = paths.tmpfile(prefix="tsmss-test-", suffix=".json")
        d = paths.tmpdir(prefix="tsmss-dir-")
        try:
            f.write_text("ok", encoding="utf-8")
            self.assertEqual(f.read_text(encoding="utf-8"), "ok")
            self.assertTrue(d.is_dir())
        finally:
            f.unlink(missing_ok=True)
            d.rmdir()

    def test_nonexistent_tempdir_exits_with_code_3(self) -> None:
        with patch.object(tempfile, "gettempdir", return_value="/nonexistent_tsmss_root_tmp_99999"):
            with self.assertRaises(SystemExit) as ctx:
                paths.startup_probe()
            self.assertEqual(ctx.exception.code, 3)

    def test_nonexistent_tempdir_error_message(self) -> None:
        import io
        from contextlib import redirect_stderr

        err_buf = io.StringIO()
        with patch.object(tempfile, "gettempdir", return_value="/nonexistent_tsmss_root_tmp_99999"):
            with redirect_stderr(err_buf):
                with self.assertRaises(SystemExit) as ctx:
                    paths.startup_probe()
        self.assertEqual(ctx.exception.code, 3)
        self.assertIn("no writable temp directory", err_buf.getvalue())

    def test_zero_byte_body_validation_positive_and_negative(self) -> None:
        # Negative: 0-byte body on HTTP 200 without Content-Length: 0 is a failed fetch
        ok, err = paths.validate_response_body("", {"content-type": "text/html"}, 200, "GET")
        self.assertFalse(ok)
        self.assertTrue(bool(err))

        # Positive: 0-byte body with explicit Content-Length: 0 is valid
        ok_cl0, err_cl0 = paths.validate_response_body("", {"content-length": "0"}, 200, "GET")
        self.assertTrue(ok_cl0)
        self.assertEqual(err_cl0, "")

        # Positive: 204 No Content and HEAD are valid with 0 bytes
        ok_204, _ = paths.validate_response_body("", {}, 204, "GET")
        self.assertTrue(ok_204)
        ok_head, _ = paths.validate_response_body("", {}, 200, "HEAD")
        self.assertTrue(ok_head)


if __name__ == "__main__":
    unittest.main()
