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
        runner = ToolRunner(ctx.config, ctx.target, ctx.evidence)
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
                if found:
                    out.append(self.make(
                        ctx, title=f"{spec.id} reported {len(found)} item(s)",
                        severity=INFO, detection_method=f"external tool {spec.id}",
                        confidence=HIGH_CONF,
                        description=f"{spec.id} finished and produced {len(found)} parsed item(s).",
                        evidence="\n".join(f.title for f in found[:15]),
                        remediation=f"Review the {spec.id} output below.",
                        tags=["external", spec.id]))
        finally:
            runner.cleanup()
        return out
