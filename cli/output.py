from __future__ import annotations

import asyncio

from fuzzer import FuzzerEngine


async def progress_printer(
    engine: FuzzerEngine,
    total_requests: int,
    scan_task: asyncio.Task,
    *,
    overall_total: int | None = None,
    baseline_completed: int = 0,
    label: str = "",
) -> None:
    """Pipeline mode: pass overall_total + baseline_completed for cumulative progress."""
    prefix = f"{label} " if label else ""

    while not scan_task.done():
        if overall_total is not None:
            completed = baseline_completed + engine.stats.completed
            # Planned denominator only — do not add queued (double-counts pipeline work).
            effective_total = max(overall_total, completed, 1)
        else:
            effective_total = max(total_requests, engine.stats.completed, 1)
            completed = engine.stats.completed

        raw = min(99.9, (completed / effective_total) * 100)
        print(
            f"\r{prefix}Progress: {raw:6.2f}% ({completed}/{effective_total})",
            end="",
            flush=True,
        )
        await asyncio.sleep(0.2)

    if overall_total is not None:
        completed = baseline_completed + engine.stats.completed
        effective_total = max(overall_total, completed, 1)
        percent = min(100.0, (completed / effective_total) * 100)
    else:
        effective_total = max(total_requests, engine.stats.completed, 1)
        completed = engine.stats.completed
        percent = 100.0

    print(
        f"\r{prefix}Progress: {percent:6.2f}% ({completed}/{effective_total})",
        end="",
        flush=True,
    )
    print()


def print_scan_configuration(
    *,
    base_url: str,
    scan_id: str,
    surface_count: int,
    attack_type: str,
    module_count: int,
    payload_count: int,
    level: int | None,
    target_dbms: str,
    target_os: str,
    oob_domain: str,
    redis_url: str,
    sqli_evasion_level: int,
    osci_evasion_level: int,
    lfi_evasion_level: int,
    ssrf_evasion_level: int,
    ssrf_oob: bool,
    sqli_time_based: bool,
    sqli_time_max: int,
    osci_time_based: bool,
    osci_time_max: int,
    total_requests: int,
    rps: int,
    delay: float,
    queue_workers: int,
    session_pool_size: int,
) -> None:
    print("=" * 60)
    print(f"Scan ID:        {scan_id}")
    print(f"Target URL:     {base_url}")
    print(f"Target DBMS:    {target_dbms}")
    print(f"Target OS:      {target_os}")
    print(f"OOB Domain:     {oob_domain}")
    print(f"Redis URL:      {redis_url}")
    print(f"Surface count:  {surface_count}")
    print(f"Attack type:    {attack_type}")
    print(f"Module count:   {module_count}")
    print(f"Payload count:  {payload_count}")
    if level is not None:
        print(
            f"Unified --level: {level} "
            "(SQLi/OSCi/LFI/SSRF; SSRF effective level capped at 2)"
        )
    print(f"SQLi evasion:   level {sqli_evasion_level}")
    print(f"OSCi evasion:   level {osci_evasion_level}")
    print(f"LFI evasion:    level {lfi_evasion_level}")
    ssrf_line = f"SSRF evasion:   level {ssrf_evasion_level}"
    if ssrf_oob:
        ssrf_line += " (+ OOB/template payloads)"
    print(ssrf_line)
    sqli_time_max_note = "all" if sqli_time_max == 0 else str(sqli_time_max)
    print(
        "SQLi timing:    "
        + ("included" if sqli_time_based else "excluded (fast mode)")
        + (f", max={sqli_time_max_note}" if sqli_time_based else "")
    )
    osci_time_max_note = "all" if osci_time_max == 0 else str(osci_time_max)
    print(
        "OSCI timing:    "
        + ("included" if osci_time_based else "excluded (fast mode)")
        + (f", max={osci_time_max_note}" if osci_time_based else "")
    )
    print(f"Total requests: {total_requests}")
    print(f"Throttle (rps): {rps} (delay {delay:.3f}s)")
    print(f"Queue workers:  {queue_workers}")
    print(f"Session pool:   {session_pool_size}")
    print("=" * 60 + "\n")