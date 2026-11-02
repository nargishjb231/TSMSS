#!/usr/bin/env python3
"""Standalone Verification Skill Script: CORS."""
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
from verification.playbooks.cors import evaluate_cors_response


def main() -> int:
    parser = argparse.ArgumentParser(description="TSMSS CORS Verification Skill")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--origin", default="https://evil.example", help="Test origin header")
    args = parser.parse_args()

    async def _test() -> tuple[bool, str, str]:
        resp = await fetch(args.url, headers={"Origin": args.origin})
        return evaluate_cors_response(resp.headers, probe_origin=args.origin)

    ok, sev, reason = asyncio.run(_test())
    payload = {
        "class": "CORS",
        "url": args.url,
        "origin": args.origin,
        "confidence": CONFIRMED if ok else "CANDIDATE",
        "severity": sev,
        "evidence": reason,
    }
    print(json.dumps(payload, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
