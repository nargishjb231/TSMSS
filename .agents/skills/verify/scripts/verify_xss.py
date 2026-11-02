#!/usr/bin/env python3
"""Standalone Verification Skill Script: Cross-Site Scripting (XSS)."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from verification.context import generate_probe_token
from verification.doctrine import CONFIRMED, CTX_MARKUP
from verification.playbooks.xss import run_xss_playbook


def main() -> int:
    parser = argparse.ArgumentParser(description="TSMSS XSS Verification Skill")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", required=True, help="Vulnerable parameter name")
    parser.add_argument("--token", default="", help="Unique token (auto-generated if empty)")
    args = parser.parse_args()

    token = args.token or generate_probe_token()
    result = asyncio.run(run_xss_playbook(args.url, args.param, token, CTX_MARKUP))
    payload = {
        "class": "XSS",
        "url": args.url,
        "param": args.param,
        "token": token,
        "confidence": result.confidence,
        "oracle": result.oracle_name,
        "repro": result.g4_repro,
        "killed": result.killed,
        "kill_reason": result.kill_reason,
    }
    print(json.dumps(payload, indent=2))
    return 0 if result.confidence == CONFIRMED else 1


if __name__ == "__main__":
    sys.exit(main())
