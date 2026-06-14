from __future__ import annotations

import asyncio
from collections.abc import Iterable, Iterator
from typing import Any


class ModulePayloadSource:
    """
    Lazy payload access for attack modules.

  - Prefers get_payload_count() for queue accounting (no materialization).
  - Materializes get_payloads() on first iterate() when caching is enabled.
  - Re-materializes each iterate() when caching is disabled.
    """

    __slots__ = ("_module", "_cache_enabled", "_cached", "_count", "_lock")

    def __init__(self, module: Any, *, cache_enabled: bool = True) -> None:
        self._module = module
        self._cache_enabled = cache_enabled
        self._cached: list[Any] | None = None
        self._count: int | None = None
        self._lock = asyncio.Lock()

    def count(self) -> int:
        if self._count is not None:
            return self._count

        counter = getattr(self._module, "get_payload_count", None)
        if callable(counter):
            self._count = max(0, int(counter()))
            return self._count

        self._count = sum(1 for _ in self._materialize())
        return self._count

    def iterate(self) -> Iterator[Any]:
        if self._cache_enabled and self._cached is not None:
            yield from self._cached
            return
        yield from self._materialize()

    async def ensure_cached(self) -> list[Any]:
        if self._cache_enabled and self._cached is not None:
            return self._cached
        async with self._lock:
            if self._cache_enabled and self._cached is not None:
                return self._cached
            payloads = list(self._materialize())
            if self._cache_enabled:
                self._cached = payloads
                if self._count is None:
                    self._count = len(payloads)
            return payloads

    def _materialize(self) -> Iterable[Any]:
        raw = self._module.get_payloads()
        if isinstance(raw, list):
            if self._cache_enabled:
                self._cached = raw
            yield from raw
            return
        if isinstance(raw, tuple):
            if self._cache_enabled:
                self._cached = list(raw)
            yield from raw
            return
        materialized = list(raw)
        if self._cache_enabled:
            self._cached = materialized
        yield from materialized


def iter_attack_batches(
    params: tuple[str, ...],
    payloads: Iterable[Any],
    batch_size: int,
) -> Iterator[list[tuple[str, Any]]]:
    """Stream param×payload combinations in fixed-size batches without building the full cross product."""
    size = max(1, batch_size)
    batch: list[tuple[str, Any]] = []
    for parameter in params:
        for payload in payloads:
            batch.append((parameter, payload))
            if len(batch) >= size:
                yield batch
                batch = []
    if batch:
        yield batch
