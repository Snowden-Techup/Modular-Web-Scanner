"""Temporary crawl path trace writer (debug). Remove when crawl stability is fixed."""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path


def build_crawl_path_log_filename(prefix: str = "crawl_path_debug") -> str:
    """One log file per crawl run (timestamp precision: seconds)."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{stamp}.txt"


class CrawlPathTrace:
    """Append-only, asyncio-safe crawl event log."""

    def __init__(self, output_path: str) -> None:
        self.output_path = Path(output_path)
        self._lock = asyncio.Lock()
        self._seq = 0

    def reset(self, start_url: str) -> None:
        self._seq = 0
        header = (
            "# crawl path trace (temporary debug)\n"
            f"# started: {datetime.now().isoformat()}\n"
            f"# start_url: {start_url}\n"
            "# columns: seq time worker event depth url | detail\n\n"
        )
        self.output_path.write_text(header, encoding="utf-8")

    async def log(
        self,
        event: str,
        *,
        url: str = "",
        depth: int | None = None,
        detail: str = "",
        worker_id: int | None = None,
    ) -> None:
        async with self._lock:
            self._seq += 1
            parts: list[str] = [
                f"{self._seq:05d}",
                datetime.now().strftime("%H:%M:%S.%f")[:-3],
            ]
            if worker_id is not None:
                parts.append(f"w{worker_id}")
            parts.append(event)
            if depth is not None:
                parts.append(f"depth={depth}")
            if url:
                parts.append(url)
            if detail:
                parts.append(f"| {detail}")
            line = "\t".join(parts) + "\n"
            with self.output_path.open("a", encoding="utf-8") as fp:
                fp.write(line)

    async def summary(self, *, visited: int, queued_remaining: int, stats: dict) -> None:
        await self.log(
            "CRAWL_END",
            detail=(
                f"visited={visited} queue_remaining={queued_remaining} "
                f"successful_requests={stats.get('successful_requests')} "
                f"failed_requests={stats.get('failed_requests')} "
                f"forms_found={stats.get('forms_found')} "
                f"links_found={stats.get('links_found')} "
                f"duration={stats.get('duration')}"
            ),
        )
