from __future__ import annotations

import asyncio
import copy
import gc
import os
from pathlib import Path

import aiohttp

from cli.output import print_scan_configuration, progress_printer
from fuzzer.runtime_config import apply_module_runtime_policy
from fuzzer import EngineStats, FuzzerEngine, Finding
from fuzzer.auth_provider import merge_scan_cookies, scan_auth_lifecycle
from fuzzer.request_builder import build_and_send_request, FuzzerResponse
from fuzzer.setup import count_module_payloads, estimate_total_requests, pipeline_module_types, select_modules
from reporter import ReportGenerator
from core.models import Payload 

def prepare_scan_context(args, surfaces):
    if args.type == "stored_xss":
        from fuzzer.runtime_config import get_fuzzer_runtime_config

        sx = get_fuzzer_runtime_config().stored_xss
        requested_rps = max(1, int(getattr(args, "rps", 50) or 50))
        args.rps = min(requested_rps, sx.max_concurrent_requests)
        requested_workers = int(getattr(args, "workers", 0) or 0)
        args.workers = (
            min(requested_workers, sx.max_workers)
            if requested_workers > 0
            else sx.max_workers
        )
        print(
            f"[SYSTEM] stored_xss 모듈 감지: RPS {args.rps}, workers {args.workers} "
            f"(FUZZER_STORED_XSS_MAX_CONCURRENT / MAX_WORKERS)"
        )
    elif args.type == "sqli":
        args.workers = 2
        print("[SYSTEM] sqli 모듈 감지: 강제로 Worker 2로 하향 조정합니다.")

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

async def poll_oob_results(modules: list, oob_domain: str) -> list[Finding]:
    """
    모든 스캔이 종료된 후, OOB 모듈들이 발급했던 토큰을 모아
    콜백 서버에 결과를 폴링. (URL Too Long 방지 청크 분할 및 네트워크 재시도 적용)
    """
    oob_findings = []
    
    # 1. 모든 OOB 모듈에서 생성했던 CLI용 토큰들을 수집
    tokens_to_poll = []
    token_map = {}
    for module in modules:
        if hasattr(module, "generated_tokens") and module.generated_tokens:
            for item in module.generated_tokens:
                token = item.token if hasattr(item, "token") else item.get("token")
                if not token:
                    continue
                tokens_to_poll.append(token)
                token_map[token] = (module, item)

    if not tokens_to_poll:
        return oob_findings

    print("\n[*] Waiting 10 seconds for delayed OOB callbacks...")
    await asyncio.sleep(10.0)
    
    # 콜백 서버 폴링 API 주소
    api_url = f"http://{oob_domain}:8001/api/poll"
    
    # URL Too Long (414/400) 에러를 막기 위해 최대 500개씩 청크 분할
    CHUNK_SIZE = 500
    token_chunks = [tokens_to_poll[i:i + CHUNK_SIZE] for i in range(0, len(tokens_to_poll), CHUNK_SIZE)]
    max_retries = 3
    
    async with aiohttp.ClientSession() as session:
        for i, chunk in enumerate(token_chunks):
            params = {"tokens": ",".join(chunk)}
            chunk_success = False
            
            # 네트워크 에러 및 타임아웃 방어용 재시도 루프
            for attempt in range(1, max_retries + 1):
                try:
                    async with session.get(api_url, params=params, timeout=10.0) as res:
                        if res.status == 200:
                            data = await res.json()
                            hits = data.get("hits", [])
                            
                            # 3. 받아온 결과를 스캐너의 Finding 객체로 변환
                            for hit in hits:
                                hit_token = hit.get("token")
                                if hit_token in token_map:
                                    matched_module, matched_info = token_map[hit_token]
                                    if hasattr(matched_info, "to_poll_dict"):
                                        matched_info = matched_info.to_poll_dict()
                                    target_url = matched_info.get("target", {}).get("url", "Unknown URL")
                                    param_name = matched_info.get("target", {}).get("parameter", "Unknown")
                                    protocol = hit.get("protocol", "Unknown")
                                    client_ip = hit.get("source_ip", "Unknown")
                                    
                                    dummy_response = FuzzerResponse(
                                        status=0, text="", headers={}, elapsed_time=0.0, url=target_url, error="OOB Callback (No Response)"
                                    )

                                    attack_info = matched_info.get("attack_info", {})

                                    reconstructed_payload = Payload(
                                        value=attack_info.get("payload_value", ""),
                                        attack_type=attack_info.get("type", "OOB"),
                                        risk_level=attack_info.get("risk_level", "High")
                                    )

                                    surface = None
                                    if hasattr(matched_module, "resolve_surface_for_token"):
                                        surface = matched_module.resolve_surface_for_token(matched_info)
                                    if surface is None:
                                        surface = matched_info.get("surface_obj")

                                    oob_findings.append(Finding(
                                        surface=surface,
                                        parameter=param_name,
                                        payload=reconstructed_payload,
                                        response=dummy_response,
                                        module_name=matched_info.get("module_name", "OOB Module"),
                                        evidences=[f"[Verified] OOB Execution detected via {protocol} from Target IP: {client_ip}"]
                                    ))
                            
                            chunk_success = True
                            break
                        else:
                            print(f"[-] OOB Polling failed for chunk {i+1} with status {res.status}. Attempt {attempt}/{max_retries}")
                            
                except Exception as e:
                    print(f"[-] OOB Polling Network Error for chunk {i+1}: {e}. Attempt {attempt}/{max_retries}")
                
                # 실패 시 2초 대기 후 재시도
                if attempt < max_retries:
                    await asyncio.sleep(2.0)
            
            if not chunk_success:
                print(f"[-] OOB Polling completely failed for chunk {i+1} after {max_retries} attempts. Some findings might be lost.")
                    
            # 서버 부하 방지를 위해 청크 간 짧은 대기 (마지막 청크 제외)
            if i < len(token_chunks) - 1:
                await asyncio.sleep(0.5)
                
    return oob_findings


async def run_scan(args, *, base_url: str, surfaces) -> None:
    from fuzzer.memory_monitor import scan_memory_monitor

    scan_label = getattr(args, "scan_id", None) or "cli"
    async with scan_memory_monitor(f"scan:{scan_label}"):
        if args.type == "all":
            await _run_scan_pipeline(args, base_url=base_url, surfaces=surfaces)
        else:
            await _run_scan_single(args, base_url=base_url, surfaces=surfaces)


async def _run_scan_single(args, *, base_url: str, surfaces) -> None:
    apply_module_runtime_policy(args.type)
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

    # 스캔 완료 직후 리포트 생성 전에 OOB 폴링 수행
    oob_domain = getattr(args, "oob_domain", "oob.snowden.kr")
    oob_findings = await poll_oob_results(context["modules"], oob_domain)

    final_findings = engine.findings
    
    if oob_findings:
        final_findings.extend(oob_findings)
        stats.findings += len(oob_findings)

    reporter = ReportGenerator(stats=stats, findings=final_findings)
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
    pipeline_modules: list = []

    scan_cookies = merge_scan_cookies(args, surfaces)

    pipeline_types = pipeline_module_types(args)

    module_totals: dict[str, int] = {}
    for mtype in pipeline_types:
        mod_args = copy.copy(args)
        mod_args.type = mtype
        mods = select_modules(mod_args)
        if mods:
            module_totals[mtype] = estimate_total_requests(surfaces, mods)
        del mods  # 추정용 모듈 인스턴스를 즉시 해제 (페이로드 캐시 포함)
    overall_total = max(1, sum(module_totals.values()))
    n_modules = len([t for t in pipeline_types if module_totals.get(t, 0) > 0])
    cumulative_completed = 0

    separator = "=" * 60
    print(f"\n{separator}")
    print(f"Pipeline mode: {n_modules} modules will run sequentially.")
    print(f"Estimated total requests: {overall_total}")
    print(f"Intermediate reports: {out_path.stem}_<module>{out_path.suffix}")
    print(f"Final merged report : {out_path.name}")
    print(separator)

    async with scan_auth_lifecycle(args, base_cookies=scan_cookies):
        module_run_idx = 0
        for idx, module_type in enumerate(pipeline_types, 1):
            mod_args = copy.copy(args)
            mod_args.type = module_type
            apply_module_runtime_policy(module_type)

            context = prepare_scan_context(mod_args, surfaces)
            if context is None or module_totals.get(module_type, 0) == 0:
                print(f"\n[{idx}/{len(pipeline_types)}] {module_type}: skipped (no payloads/surfaces).")
                continue

            module_run_idx += 1
            print(f"\n{separator}")
            print(
                f"[{module_run_idx}/{n_modules}] Module: {module_type}  "
                f"({context['total_requests']} requests, "
                f"overall {cumulative_completed}/{overall_total})"
            )
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
                progress_printer(
                    engine,
                    context["total_requests"],
                    scan_task,
                    overall_total=overall_total,
                    baseline_completed=cumulative_completed,
                    label=f"[{module_run_idx}/{n_modules} {module_type}]",
                )
            )
            stats = await scan_task
            await progress_task
            cumulative_completed += stats.completed

            # 모듈별 중간 리포트 저장
            module_output = out_path.with_name(
                f"{out_path.stem}_{module_type}{out_path.suffix}"
            )
            # [OOM Fix #3] engine._findings 직접 참조 — engine.findings(복사본) 대신 사용
            module_reporter = ReportGenerator(stats=stats, findings=engine._findings)
            module_reporter.print_cli_report()
            module_reporter.export_to_json(str(module_output))
            print(f"  → intermediate report: {module_output.name}  "
                  f"(findings={stats.findings})")

            # [OOM Fix #4] response.text는 중간 리포트까지만 필요하다.
            # all_findings에 옮기기 전에 5 MB 짜리 응답 본문을 비워 메모리를 확보한다.
            # _finding_to_dict()는 status/elapsed_time/error만 사용하므로 손실 없음.
            module_findings = engine.consume_findings()  # 원본 리스트를 이동 (복사 없음)
            for f in module_findings:
                if f.response is not None:
                    f.response.text = ""
                    f.response.headers = {}  # 헤더도 불필요
            all_findings.extend(module_findings)
            del module_findings  # 지역 참조 즉시 해제

            merged_stats.queued += stats.queued
            merged_stats.completed += stats.completed
            merged_stats.failures += stats.failures
            merged_stats.findings += stats.findings

            # [OOM Fix #2] OOB 모듈만 pipeline_modules에 보존한다.
            # poll_oob_results()는 generated_tokens 속성을 가진 모듈만 필요하며,
            # 나머지 모듈 인스턴스(+ 내부 페이로드 캐시)는 즉시 해제한다.
            pipeline_modules.extend(
                m for m in context["modules"] if hasattr(m, "generated_tokens")
            )

            # 모듈 간 GC를 강제해 Python 힙이 OS에 메모리를 돌려줄 수 있게 한다
            gc.collect()

    oob_domain = getattr(args, "oob_domain", "oob.snowden.kr")
    oob_findings = await poll_oob_results(pipeline_modules, oob_domain)
    if oob_findings:
        all_findings.extend(oob_findings)
        merged_stats.findings += len(oob_findings)

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