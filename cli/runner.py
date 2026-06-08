from __future__ import annotations

import asyncio
import os
import aiohttp

from cli.output import print_scan_configuration, progress_printer
from fuzzer import FuzzerEngine, Finding
from fuzzer.auth_provider import merge_scan_cookies, scan_auth_lifecycle
from fuzzer.request_builder import build_and_send_request, FuzzerResponse
from fuzzer.setup import count_module_payloads, estimate_total_requests, select_modules
from reporter import ReportGenerator
from core.models import Payload 

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

async def poll_oob_results(modules: list, oob_domain: str) -> list[Finding]:
    """
    모든 스캔이 종료된 후, OOB 모듈들이 발급했던 토큰을 모아
    콜백 서버에 결과를 폴링. (URL Too Long 방지를 위해 청크 분할 전송)
    """
    oob_findings = []
    
    # 1. 모든 OOB 모듈에서 생성했던 CLI용 토큰들을 수집
    tokens_to_poll = []
    token_map = {}
    for module in modules:
        if hasattr(module, "generated_tokens") and module.generated_tokens:
            for item in module.generated_tokens:
                tokens_to_poll.append(item["token"])
                token_map[item["token"]] = item

    if not tokens_to_poll:
        return oob_findings

    print("\n[*] Waiting 10 seconds for delayed OOB callbacks...")
    await asyncio.sleep(10.0)
    
    # 콜백 서버 폴링 API 주소
    api_url = f"http://{oob_domain}:8001/api/poll"
    
    # URL Too Long (414/400) 에러를 막기 위해 최대 500개씩 청크 분할
    CHUNK_SIZE = 500
    token_chunks = [tokens_to_poll[i:i + CHUNK_SIZE] for i in range(0, len(tokens_to_poll), CHUNK_SIZE)]
    
    try:
        async with aiohttp.ClientSession() as session:
            for i, chunk in enumerate(token_chunks):
                # 2. API 호출 (청크 단위로 발송)
                params = {"tokens": ",".join(chunk)}
                
                async with session.get(api_url, params=params, timeout=10.0) as res:
                    if res.status == 200:
                        data = await res.json()
                        hits = data.get("hits", [])
                        
                        # 3. 받아온 결과를 스캐너의 Finding 객체로 변환
                        for hit in hits:
                            hit_token = hit.get("token")
                            if hit_token in token_map:
                                matched_info = token_map[hit_token]
                                target_url = matched_info.get("target", {}).get("url", "Unknown URL")
                                param_name = matched_info.get("target", {}).get("parameter", "Unknown")
                                protocol = hit.get("protocol", "Unknown")
                                client_ip = hit.get("source_ip", "Unknown")
                                
                                print(f"[+] [OOB Hit] Vulnerability Verified on {target_url} (Param: {param_name}) via {protocol}")
                                dummy_response = FuzzerResponse(
                                    status=0, text="", headers={}, elapsed_time=0.0, url=target_url, error="OOB Callback (No Response)"
                                )

                                attack_info = matched_info.get("attack_info", {})

                                reconstructed_payload = Payload(
                                    value=attack_info.get("payload_value", ""),
                                    attack_type=attack_info.get("type", "OOB"),
                                    risk_level=attack_info.get("risk_level", "High")
                                )

                                oob_findings.append(Finding(
                                    surface=matched_info["surface_obj"],
                                    parameter=param_name,
                                    payload=reconstructed_payload,
                                    response=dummy_response,
                                    module_name=matched_info.get("module_name", "OOB Module"),
                                    evidences=[f"[Verified] OOB Execution detected via {protocol} from Target IP: {client_ip}"]
                                ))
                    else:
                        print(f"[-] OOB Polling failed for chunk {i+1} with status {res.status}")
                        
                # 서버 부하 방지를 위해 청크 간 짧은 대기
                if i < len(token_chunks) - 1:
                    await asyncio.sleep(0.5)

    except Exception as e:
        print(f"[-] OOB Polling Network Error: {e}")
        
    return oob_findings


async def run_scan(args, *, base_url: str, surfaces) -> None:
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
        worker_count=context["queue_workers"],  # queue consumption workers
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


async def _request_sender(session, surface, parameter, payload, allow_redirects=True):
    return await build_and_send_request(session, surface, parameter, payload, allow_redirects=allow_redirects)