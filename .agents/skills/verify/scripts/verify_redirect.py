#!/usr/bin/env python3
"""Standalone Verification Skill Script: Open Redirect."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from net.client import fetch
from verification.doctrine import CONFIRMED
from verification.playbooks.open_redirect import REDIRECT_PROBES, evaluate_open_redirect


def main() -> int:
    parser = argparse.ArgumentParser(description="TSMSS Open Redirect Verification Skill")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", required=True, help="Parameter name")
    args = parser.parse_args()

    delim = "&" if "?" in args.url else "?"
    t_host = urlparse(args.url).netloc
    confirmed = False
    evidence = ""

    async def _test() -> None:
        nonlocal confirmed, evidence
        for probe in REDIRECT_PROBES:
            test_url = f"{args.url}{delim}{args.param}={probe}"
            resp = await fetch(test_url, follow_redirects=False)
            loc = resp.headers.get("location")
            ok, reason = evaluate_open_redirect(resp.status, loc, t_host)
            if ok:
                confirmed = True
                evidence = reason
                break

    asyncio.run(_test())
    payload = {
        "class": "OpenRedirect",
        "url": args.url,
        "param": args.param,
        "confidence": CONFIRMED if confirmed else "CANDIDATE",
        "oracle": "Location header external destination" if confirmed else "None",
        "evidence": evidence,
    }
    print(json.dumps(payload, indent=2))
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
