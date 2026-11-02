#!/usr/bin/env python3
"""Standalone Verification Skill Script: Insecure Direct Object Reference (IDOR)."""
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
from verification.playbooks.cache_deception import evaluate_idor_mutation


def main() -> int:
    parser = argparse.ArgumentParser(description="TSMSS IDOR Verification Skill")
    parser.add_argument("--url", required=True, help="Original URL (e.g. /api/user/1001)")
    parser.add_argument("--mutated-url", required=True, help="Mutated URL (e.g. /api/user/1002)")
    args = parser.parse_args()

    async def _test() -> tuple[bool, str]:
        r1 = await fetch(args.url)
        r2 = await fetch(args.mutated_url)
        return evaluate_idor_mutation(r1.status, r1.body or "", r2.status, r2.body or "", "IDOR_MUTATION")

    ok, reason = asyncio.run(_test())
    payload = {
        "class": "IDOR",
        "url": args.url,
        "mutated_url": args.mutated_url,
        "confidence": CONFIRMED if ok else "CANDIDATE",
        "evidence": reason,
    }
    print(json.dumps(payload, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
