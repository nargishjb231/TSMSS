#!/usr/bin/env python3
"""Standalone Verification Skill Script: Server-Side Request Forgery (SSRF)."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from verification.doctrine import CONFIRMED
from verification.playbooks.ssrf import run_ssrf_playbook


def main() -> int:
    parser = argparse.ArgumentParser(description="TSMSS SSRF Verification Skill")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", required=True, help="Parameter name")
    parser.add_argument("--interactsh", default="", help="Interactsh host (optional)")
    args = parser.parse_args()

    result = asyncio.run(run_ssrf_playbook(args.url, args.param, interactsh_host=args.interactsh or None))
    payload = {
        "class": "SSRF",
        "url": args.url,
        "param": args.param,
        "confidence": result.confidence,
        "oracle": result.oracle_name,
        "repro": result.g4_repro,
        "evidence": result.evidence_text,
        "kill_reason": result.kill_reason,
    }
    print(json.dumps(payload, indent=2))
    return 0 if result.confidence == CONFIRMED else 1


if __name__ == "__main__":
    sys.exit(main())
