#!/usr/bin/env python3
"""Standalone Verification Skill Script: JWT."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from verification.doctrine import CONFIRMED
from verification.playbooks.jwt import parse_jwt


def main() -> int:
    parser = argparse.ArgumentParser(description="TSMSS JWT Verification Skill")
    parser.add_argument("--token", required=True, help="JWT string")
    args = parser.parse_args()

    try:
        hdr, pld, sig = parse_jwt(args.token)
        alg = hdr.get("alg", "")
        payload = {
            "class": "JWT",
            "alg": alg,
            "header": hdr,
            "payload": pld,
            "is_none_alg": alg.lower() == "none",
        }
        print(json.dumps(payload, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
