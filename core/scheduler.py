"""Batch scheduler: bounded concurrency, checkpoints, resumption, emergency stop."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from core.logger import get

log = get("tsmss.scheduler")


@dataclass
class BatchState:
    total: int = 0
    completed: int = 0
    failed: int = 0
    skipped: int = 0
    pending: int = 0
    current: list[str] = field(default_factory=list)
    requests: int = 0
    started: float = field(default_factory=time.monotonic)

    @property
    def elapsed(self) -> int:
        return int(time.monotonic() - self.started)

    @property
    def done(self) -> int:
        return self.completed + self.failed + self.skipped


class Scheduler:
    """Runs targets in batches with a concurrency ceiling and per-target checkpoints."""

    def __init__(self, config, stop_event: asyncio.Event, on_target_done: Callable,
                 on_progress: Callable[[BatchState], None] | None = None):
        self.config = config
        self.stop_event = stop_event
        self.on_target_done = on_target_done
        self.on_progress = on_progress
        self.concurrency = int(config.get("scan.concurrency_targets", 3))
        self.batch_size = int(config.get("scan.batch_size", 5))
        self.state = BatchState()

    async def run(self, urls: list[str],
                  worker: Callable[[str], Awaitable[tuple]]) -> None:
        self.state.total = len(urls)
        self.state.pending = len(urls)
        sem = asyncio.Semaphore(self.concurrency)
        queue: asyncio.Queue[str] = asyncio.Queue()
        for u in urls:
            queue.put_nowait(u)

        async def runner(url: str) -> None:
            async with sem:
                if self.stop_event.is_set():
                    self.state.skipped += 1
                    self.state.pending -= 1
                    return
                self.state.current.append(url)
                self._report()
                try:
                    result = await worker(url)
                    ok = not result[2] if len(result) > 2 else True
                except asyncio.CancelledError:
                    self.state.skipped += 1
                    raise
                except Exception as exc:  # noqa: BLE001
                    log.warning("worker crash on %s: %s", url, exc)
                    result, ok = (url, [], 0, str(exc), 0), False
                finally:
                    if url in self.state.current:
                        self.state.current.remove(url)
                self.state.requests += int(result[4]) if len(result) > 4 else 0
                self.state.pending -= 1
                if ok:
                    self.state.completed += 1
                else:
                    self.state.failed += 1
                await self.on_target_done(url, result)
                self._report()

        tasks = [asyncio.create_task(runner(u)) for u in urls]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()
            raise

    def _report(self) -> None:
        if self.on_progress:
            try:
                self.on_progress(self.state)
            except Exception:  # noqa: BLE001
                pass

    def request_stop(self) -> None:
        self.stop_event.set()