"""Runs enabled external tools and folds their output into findings."""
from __future__ import annotations

import asyncio

from core.finding import HIGH_CONF, INFO, LOW, MEDIUM
from core.tool_runner import ToolRunner
from modules.base import BaseModule


class ExternalToolsModule(BaseModule):
    name = "external_tools"
    category = "External Tools"

    async def run(self, ctx):
        if ctx.config.get("tools.mode", "auto") == "off":
            return []
        runner = ToolRunner(ctx.config, ctx.target, ctx.evidence, ctx=ctx)
        specs = runner.select()
        if not specs:
            return []
        out = []
        budget = float(ctx.config.get("tools.max_runtime", 180))
        loop = asyncio.get_event_loop()
        started = loop.time()
        try:
            for spec in specs:
                if ctx.stop_event.is_set() or loop.time() - started > budget * 3:
                    break
                found = await runner.run(spec)
                out += found
        finally:
            runner.cleanup()
        return out
