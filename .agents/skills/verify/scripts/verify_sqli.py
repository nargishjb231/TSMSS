#!/usr/bin/env python3
"""Standalone Verification Skill Script: SQL Injection (SQLi)."""
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
from verification.playbooks.sqli import run_sqli_playbook


def main() -> int:
    parser = argparse.ArgumentParser(description="TSMSS SQLi Verification Skill")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", required=True, help="Parameter name")
    args = parser.parse_args()

    result = asyncio.run(run_sqli_playbook(args.url, args.param))
    payload = {
        "class": "SQLi",
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
