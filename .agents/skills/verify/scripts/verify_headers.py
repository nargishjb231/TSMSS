#!/usr/bin/env python3
"""Standalone Verification Skill Script: Host Header Injection."""
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
from verification.playbooks.host_header import evaluate_host_header_reflection


def main() -> int:
    parser = argparse.ArgumentParser(description="TSMSS Host Header Verification Skill")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--host-value", default="evil.example", help="Injected host header value")
    args = parser.parse_args()

    async def _test() -> tuple[bool, str]:
        resp = await fetch(args.url, headers={"X-Forwarded-Host": args.host_value})
        return evaluate_host_header_reflection(resp.headers, resp.body or "", probe_host=args.host_value)

    ok, reason = asyncio.run(_test())
    payload = {
        "class": "HostHeader",
        "url": args.url,
        "host_value": args.host_value,
        "confidence": CONFIRMED if ok else "CANDIDATE",
        "evidence": reason,
    }
    print(json.dumps(payload, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
