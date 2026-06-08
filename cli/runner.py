from __future__ import annotations

import asyncio
import copy
import os
from pathlib import Path

from cli.options import parse_cookies
from cli.output import print_scan_configuration, progress_printer
from fuzzer import EngineStats, FuzzerEngine
from fuzzer.auth_provider import merge_scan_cookies, scan_auth_lifecycle
from fuzzer.request_builder import build_and_send_request
from fuzzer.setup import count_module_payloads, estimate_total_requests, pipeline_module_types, select_modules
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
    if args.type == "all":
        await _run_scan_pipeline(args, base_url=base_url, surfaces=surfaces)
    else:
        await _run_scan_single(args, base_url=base_url, surfaces=surfaces)


async def _run_scan_single(args, *, base_url: str, surfaces) -> None:
    context = prepare_scan_context(args, surfaces)
    if context is None:
        return

    print_scan_configuration(
        base_url=base_url,
        scan_id=getattr(args, "scan_id", "CLI-Local-Scan"),
        surface_count=len(surfaces),
        attack_type=args.type,
        module_count=len(context["modules"]),
        payload_count=context["payload_count"],
        level=args.level,
        target_dbms=args.target_dbms,
        target_os=args.target_os,
        oob_domain=getattr(args, "oob_domain", "oob.snowden.kr"),
        redis_url=getattr(args, "redis_url", "redis://localhost:6379/0"),
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
        worker_count=context["queue_workers"],
        modules=context["modules"],
        concurrency_per_module=context["queue_workers"],
        session_pool_size=max(1, args.session_pool_size),
        delay=context["delay"],
    )

    scan_cookies = merge_scan_cookies(args, surfaces)
    async with scan_auth_lifecycle(args, base_cookies=scan_cookies, surfaces=surfaces):
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


async def _run_scan_pipeline(args, *, base_url: str, surfaces) -> None:
    """
    -t all 전용 순차 파이프라인.

    모듈을 하나씩 실행하고, 각 모듈 완료 시 중간 리포트를 저장한다.
    전체 완료 후 모든 findings 를 합산한 최종 리포트를 args.output 에 저장한다.
    """
    out_path = Path(args.output)
    all_findings: list = []
    merged_stats = EngineStats(queued=0, completed=0, failures=0, findings=0)

    scan_cookies = parse_cookies(args.cookie) if getattr(args, "cookie", "") else {}

    pipeline_types = pipeline_module_types(args)

    separator = "=" * 60
    print(f"\n{separator}")
    print(f"Pipeline mode: {len(pipeline_types)} modules will run sequentially.")
    print(f"Intermediate reports: {out_path.stem}_<module>{out_path.suffix}")
    print(f"Final merged report : {out_path.name}")
    print(separator)

    async with scan_auth_lifecycle(args, base_cookies=scan_cookies):
        for idx, module_type in enumerate(pipeline_types, 1):
            mod_args = copy.copy(args)
            mod_args.type = module_type

            context = prepare_scan_context(mod_args, surfaces)
            if context is None:
                print(f"\n[{idx}/{len(pipeline_types)}] {module_type}: skipped (no payloads/surfaces).")
                continue

            print(f"\n{separator}")
            print(f"[{idx}/{len(pipeline_types)}] Module: {module_type}  ({context['total_requests']} requests)")
            print(separator)

            engine = FuzzerEngine(
                max_concurrent_requests=context["concurrency"],
                worker_count=context["queue_workers"],
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

            # 모듈별 중간 리포트 저장
            module_output = out_path.with_name(
                f"{out_path.stem}_{module_type}{out_path.suffix}"
            )
            module_reporter = ReportGenerator(stats=stats, findings=engine.findings)
            module_reporter.print_cli_report()
            module_reporter.export_to_json(str(module_output))
            print(f"  → intermediate report: {module_output.name}  "
                  f"(findings={stats.findings})")

            all_findings.extend(engine.findings)
            merged_stats.queued += stats.queued
            merged_stats.completed += stats.completed
            merged_stats.failures += stats.failures
            merged_stats.findings += stats.findings

    # 최종 합산 리포트
    print(f"\n{separator}")
    print("Pipeline complete. Writing merged report...")
    print(separator)
    if all_findings or merged_stats.completed > 0:
        final_reporter = ReportGenerator(stats=merged_stats, findings=all_findings)
        final_reporter.print_cli_report()
        final_reporter.export_to_json(str(out_path))
    else:
        print("No findings across all modules.")
    print(f"Merged report: {out_path}")


async def _request_sender(session, surface, parameter, payload, allow_redirects=True):
    return await build_and_send_request(session, surface, parameter, payload, allow_redirects=allow_redirects)