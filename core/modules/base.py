"""Module contract."""
from __future__ import annotations

from core.finding import Finding


class BaseModule:
    name = "base"
    category = "General"
    needs_http = True
    needs_dns = False
    needs_tls = False

    async def run(self, ctx) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError

    def make(self, ctx, **kw) -> Finding:
        kw.setdefault("category", self.category)
        kw.setdefault("module", self.name)
        kw.setdefault("target", ctx.target.url)
        return Finding(**kw)