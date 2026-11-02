#!/usr/bin/env python3
"""Standalone Verification Skill Script: GraphQL."""
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
from verification.playbooks.graphql import evaluate_graphql_introspection


def main() -> int:
    parser = argparse.ArgumentParser(description="TSMSS GraphQL Verification Skill")
    parser.add_argument("--url", required=True, help="GraphQL endpoint URL")
    args = parser.parse_args()

    query = '{"query": "{ __schema { types { name } } }"}'

    async def _test() -> tuple[bool, str]:
        resp = await fetch(args.url, method="POST", headers={"Content-Type": "application/json"}, data=query)
        return evaluate_graphql_introspection(resp.body or "")

    ok, reason = asyncio.run(_test())
    payload = {
        "class": "GraphQL",
        "url": args.url,
        "introspection_enabled": ok,
        "evidence": reason,
    }
    print(json.dumps(payload, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
