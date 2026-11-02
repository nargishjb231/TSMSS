#!/usr/bin/env python3
"""Standalone Verification Skill Script: Web Cache Deception."""
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
from verification.playbooks.cache_deception import evaluate_cache_deception


def main() -> int:
    parser = argparse.ArgumentParser(description="TSMSS Cache Deception Verification Skill")
    parser.add_argument("--url", required=True, help="Target URL (e.g. https://example.com/account/test.css)")
    args = parser.parse_args()

    async def _test() -> tuple[bool, str]:
        resp = await fetch(args.url)
        return evaluate_cache_deception(resp.headers, resp.body or "", "")

    ok, reason = asyncio.run(_test())
    payload = {
        "class": "WebCacheDeception",
        "url": args.url,
        "confidence": CONFIRMED if ok else "CANDIDATE",
        "evidence": reason,
    }
    print(json.dumps(payload, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
