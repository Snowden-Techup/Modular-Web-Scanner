from __future__ import annotations

import asyncio
import os
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, Callable, Literal

LogSink = Callable[[str], None]

_INTERVAL_ENV = "FUZZER_MEMORY_LOG_INTERVAL"
_MODE_ENV = "FUZZER_MEMORY_LOG_MODE"

MemoryLogMode = Literal["off", "interval", "module"]


@dataclass(frozen=True, slots=True)
class MemorySnapshot:
    process_rss_bytes: int
    cgroup_used_bytes: int | None
    cgroup_limit_bytes: int | None

    @property
    def cgroup_usage_ratio(self) -> float | None:
        if self.cgroup_used_bytes is None or not self.cgroup_limit_bytes:
            return None
        return self.cgroup_used_bytes / self.cgroup_limit_bytes


def memory_log_interval_seconds() -> float:
    """Seconds between periodic memory log lines (interval mode only)."""
    raw = os.getenv(_INTERVAL_ENV, "").strip()
    if not raw:
        return 0.0
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 0.0


def memory_log_mode() -> MemoryLogMode:
    """
    Memory logging strategy.

    - off: disabled
    - module: log at each attack-module start/end (pipeline or single -t)
    - interval: periodic logging every FUZZER_MEMORY_LOG_INTERVAL seconds

    FUZZER_MEMORY_LOG_MODE takes precedence. If unset, interval env > 0 implies
    interval mode; otherwise off.
    """
    raw = (os.getenv(_MODE_ENV, "") or "").strip().lower()
    if raw in ("off", "0", "false", "no", "none"):
        return "off"
    if raw in ("module", "modules", "per_module"):
        return "module"
    if raw in ("interval", "periodic"):
        return "interval"
    if memory_log_interval_seconds() > 0:
        return "interval"
    return "off"


def _read_int_file(path: Path) -> int | None:
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not raw or raw.lower() == "max":
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _process_rss_bytes() -> int:
    proc_status = Path("/proc/self/status")
    if proc_status.is_file():
        try:
            for line in proc_status.read_text(encoding="utf-8").splitlines():
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1]) * 1024
        except (OSError, ValueError):
            pass

    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == "darwin":
            return int(usage)
        return int(usage) * 1024
    except Exception:
        return 0


def _cgroup_memory_paths() -> list[tuple[Path, Path]]:
    candidates: list[tuple[Path, Path]] = [
        (Path("/sys/fs/cgroup/memory.current"), Path("/sys/fs/cgroup/memory.max")),
    ]
    v1_base = Path("/sys/fs/cgroup/memory")
    candidates.append(
        (v1_base / "memory.usage_in_bytes", v1_base / "memory.limit_in_bytes"),
    )
    return candidates


def capture_memory_snapshot() -> MemorySnapshot:
    cgroup_used: int | None = None
    cgroup_limit: int | None = None
    for used_path, limit_path in _cgroup_memory_paths():
        used = _read_int_file(used_path)
        if used is None:
            continue
        cgroup_used = used
        cgroup_limit = _read_int_file(limit_path)
        break

    return MemorySnapshot(
        process_rss_bytes=_process_rss_bytes(),
        cgroup_used_bytes=cgroup_used,
        cgroup_limit_bytes=cgroup_limit,
    )


def format_bytes(num_bytes: int) -> str:
    if num_bytes < 0:
        return "n/a"
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    size = float(num_bytes)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)}{unit}"
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{num_bytes}B"


def _format_delta(num_bytes: int) -> str:
    sign = "+" if num_bytes >= 0 else "-"
    return f"{sign}{format_bytes(abs(num_bytes))}"


def format_memory_log_line(snapshot: MemorySnapshot, *, label: str) -> str:
    parts = [
        "[memory]",
        f"label={label}",
        f"pid={os.getpid()}",
        f"rss={format_bytes(snapshot.process_rss_bytes)}",
    ]
    if snapshot.cgroup_used_bytes is not None:
        cgroup_line = f"cgroup={format_bytes(snapshot.cgroup_used_bytes)}"
        if snapshot.cgroup_limit_bytes:
            ratio = snapshot.cgroup_usage_ratio
            pct = f"{ratio * 100:.1f}%" if ratio is not None else "n/a"
            cgroup_line += f"/{format_bytes(snapshot.cgroup_limit_bytes)} ({pct})"
        parts.append(cgroup_line)
    return " ".join(parts)


def format_module_memory_end_line(
    start: MemorySnapshot,
    end: MemorySnapshot,
    *,
    module_name: str,
    duration_s: float,
) -> str:
    parts = [
        "[memory]",
        f"module={module_name}",
        "phase=end",
        f"pid={os.getpid()}",
        f"rss={format_bytes(end.process_rss_bytes)}",
        f"delta_rss={_format_delta(end.process_rss_bytes - start.process_rss_bytes)}",
        f"duration={duration_s:.1f}s",
    ]
    if end.cgroup_used_bytes is not None:
        cgroup_line = f"cgroup={format_bytes(end.cgroup_used_bytes)}"
        if end.cgroup_limit_bytes:
            ratio = end.cgroup_usage_ratio
            pct = f"{ratio * 100:.1f}%" if ratio is not None else "n/a"
            cgroup_line += f"/{format_bytes(end.cgroup_limit_bytes)} ({pct})"
        if start.cgroup_used_bytes is not None:
            cgroup_line += (
                f" delta_cgroup={_format_delta(end.cgroup_used_bytes - start.cgroup_used_bytes)}"
            )
        parts.append(cgroup_line)
    return " ".join(parts)


async def memory_log_loop(
    *,
    label: str,
    interval_seconds: float,
    stop_event: asyncio.Event,
    sink: LogSink | None = None,
) -> None:
    emit = sink or (lambda line: print(line, flush=True))
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
            break
        except asyncio.TimeoutError:
            emit(format_memory_log_line(capture_memory_snapshot(), label=label))


@asynccontextmanager
async def module_memory_span(
    module_name: str,
    *,
    sink: LogSink | None = None,
) -> AsyncIterator[None]:
    """
    Log memory at attack-module start and end with RSS/cgroup deltas.
    Active when FUZZER_MEMORY_LOG_MODE=module.
    """
    if memory_log_mode() != "module":
        yield
        return

    emit = sink or (lambda line: print(line, flush=True))
    started_at = time.monotonic()
    start_snap = capture_memory_snapshot()
    emit(format_memory_log_line(start_snap, label=f"module:{module_name}:start"))
    try:
        yield
    finally:
        end_snap = capture_memory_snapshot()
        emit(
            format_module_memory_end_line(
                start_snap,
                end_snap,
                module_name=module_name,
                duration_s=time.monotonic() - started_at,
            )
        )


@asynccontextmanager
async def scan_memory_monitor(
    label: str,
    *,
    interval_seconds: float | None = None,
    sink: LogSink | None = None,
) -> AsyncIterator[None]:
    """
    Periodic memory logging for interval mode only.
    Module-scoped logging uses module_memory_span() instead.
    """
    if memory_log_mode() != "interval":
        yield
        return

    interval = memory_log_interval_seconds() if interval_seconds is None else max(0.0, interval_seconds)
    if interval <= 0:
        yield
        return

    stop_event = asyncio.Event()
    emit = sink or (lambda line: print(line, flush=True))
    emit(
        f"[memory] monitor started label={label} interval={interval:.1f}s "
        f"ts={time.strftime('%Y-%m-%d %H:%M:%S')}"
    )
    task = asyncio.create_task(
        memory_log_loop(
            label=label,
            interval_seconds=interval,
            stop_event=stop_event,
            sink=emit,
        )
    )
    try:
        yield
    finally:
        stop_event.set()
        await task
        emit(
            f"[memory] monitor stopped label={label} "
            f"final={format_memory_log_line(capture_memory_snapshot(), label=label)}"
        )
