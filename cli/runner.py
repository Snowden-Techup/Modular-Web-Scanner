from __future__ import annotations

import asyncio
import os

from cli.output import print_scan_configuration, progress_printer
from fuzzer import FuzzerEngine
from fuzzer.request_builder import build_and_send_request
from fuzzer.setup import count_module_payloads, estimate_total_requests, select_modules
from reporter import ReportGenerator


def prepare_scan_context(args, surfaces):
    if args.type == "stored_xss":
        args.rps = 10
        args.workers = 2
        print("[SYSTEM] stored_xss 모듈 감지: 강제로 RPS 10, Worker 2로 하향 조정합니다.")

    selected_modules = select_modules(args)
    if not selected_modules:
        print(f"No modules registered for attack type {args.type!r}. Exiting.")
        return None

    if args.type == "bruteforce" and not os.path.exists(args.bf_wordlist):
        print(f"Bruteforce wordlist not found: {args.bf_wordlist}")
        return None

    payload_count = count_module_payloads(selected_modules)
    if payload_count == 0:
        print("No payloads loaded for selected modules. Exiting.")
        return None

    delay = (1.0 / args.rps) if args.rps > 0 else 0.0
    concurrency = max(1, args.rps)
    if hasattr(args, 'workers') and args.workers > 0:
        queue_workers = args.workers
    else:
        queue_workers = max(1, args.rps * 2)
    total_requests = estimate_total_requests(surfaces, selected_modules)

    return {
        "modules": selected_modules,
        "payload_count": payload_count,
        "delay": delay,
        "concurrency": concurrency,
        "queue_workers": queue_workers,
        "total_requests": total_requests,
    }


async def run_scan(args, *, base_url: str, surfaces) -> None:
    context = prepare_scan_context(args, surfaces)
    if context is None:
        return

    print_scan_configuration(
        base_url=base_url,
        surface_count=len(surfaces),
        attack_type=args.type,
        module_count=len(context["modules"]),
        payload_count=context["payload_count"],
        level=args.level,
        target_dbms=args.target_dbms, 
        target_os=args.target_os,
        sqli_evasion_level=args.sqli_evasion_level,
        osci_evasion_level=args.osci_evasion_level,
        lfi_evasion_level=args.lfi_evasion_level,
        ssrf_evasion_level=args.ssrf_evasion_level,
        ssrf_oob=args.ssrf_oob,
        sqli_time_based=args.sqli_time_based,
        sqli_time_max=args.sqli_time_max,
        osci_time_based=args.osci_time_based,
        osci_time_max=args.osci_time_max,
        total_requests=context["total_requests"],
        rps=args.rps,
        delay=context["delay"],
        queue_workers=context["queue_workers"],
        session_pool_size=args.session_pool_size,
    )

    engine = FuzzerEngine(
        max_concurrent_requests=context["concurrency"],
        worker_count=context["queue_workers"],  # queue consumption workers
        modules=context["modules"],
        concurrency_per_module=context["queue_workers"],
        session_pool_size=max(1, args.session_pool_size),
        delay=context["delay"],
    )

    scan_task = asyncio.create_task(
        engine.run_with_attack_modules(
            surfaces=surfaces,
            request_sender=_request_sender,
        )
    )
    progress_task = asyncio.create_task(
        progress_printer(engine, context["total_requests"], scan_task)
    )
    stats = await scan_task
    await progress_task

    reporter = ReportGenerator(stats=stats, findings=engine.findings)
    reporter.print_cli_report()
    reporter.export_to_json(args.output)


async def _request_sender(session, surface, parameter, payload, allow_redirects=True):
    return await build_and_send_request(session, surface, parameter, payload, allow_redirects=allow_redirects)
