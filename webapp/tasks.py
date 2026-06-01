from __future__ import annotations

import asyncio
import json
import time

from argparse import Namespace
from celery import Task

from webapp.celery_app import celery_app
from webapp.db_service import (
    append_scan_log,
    get_scan_by_public_id,
    get_scan_pk,
    replace_scan_findings,
    update_scan_fields,
)


# ─────────────────────────────────────────
# 스캔 요청 dict → Namespace (기존 _build_cli_args 로직과 동일)
# tasks.py 는 main.py 를 import 하지 않으므로 독립적으로 정의
# ─────────────────────────────────────────
def _build_args_from_payload(payload: dict) -> Namespace:
    from cli.options import parse_bf_length

    bf = payload.get("bruteforce", {})
    engine = payload.get("engine", {})
    auth = payload.get("auth", {})
    sqli = payload.get("sqli", {})
    osci = payload.get("osci", {})
    ssrf = payload.get("ssrf", {})
    sxss = payload.get("stored_xss", {})
    rxss = payload.get("reflected_xss", {})
    oob = payload.get("oob", {})

    level = int(payload.get("level", 1))
    bf_min = int(bf.get("bf_min_length", 1))
    bf_max = int(bf.get("bf_max_length", 3))
    bf_length_str = str(bf.get("bf_length", "") or "")
    if bf_length_str.strip():
        try:
            bf_min, bf_max = parse_bf_length(bf_length_str, bf_max)
        except ValueError:
            pass

    from modules.oob.client import DEFAULT_OAST_SERVER_URL, normalize_oast_server_url
    oob_server_raw = oob.get("oob_server", DEFAULT_OAST_SERVER_URL) or DEFAULT_OAST_SERVER_URL

    return Namespace(
        url=payload.get("url") or payload.get("target_url", ""),
        rps=int(engine.get("rps", 50)),
        cookie=auth.get("cookie", ""),
        login_url=auth.get("login_url", ""),
        username=auth.get("username", ""),
        password=auth.get("password", ""),
        username_field=auth.get("username_field", "username"),
        password_field=auth.get("password_field", "password"),
        csrf_field=auth.get("csrf_field", "user_token"),
        submit_field=auth.get("submit_field", "Login"),
        output=engine.get("output", "scan_report.json"),
        surfaces_output=engine.get("surfaces_output", "attack_surfaces.json"),
        type=payload.get("scan_type", "all"),
        session_pool_size=int(engine.get("session_pool_size", 3)),
        level=level,
        bf_wordlist=bf.get("bf_wordlist", "config/payloads/bruteforce/common_passwords.txt"),
        bf_disable_mutation=bool(bf.get("bf_disable_mutation", False)),
        bf_mutation_level=int(bf.get("bf_mutation_level", 1)),
        bf_true_random=bool(bf.get("bf_true_random", False)),
        bf_charset=bf.get("bf_charset", "abcdefghijklmnopqrstuvwxyz0123456789"),
        bf_min_length=bf_min,
        bf_max_length=bf_max,
        bf_length=bf_length_str,
        bf_max_dictionary=int(bf.get("bf_max_dictionary", 0)),
        bf_max_true_random=int(bf.get("bf_max_true_random", 0)),
        bf_stop_on_first_hit=bool(bf.get("bf_stop_on_first_hit", True)),
        bf_target_url=bf.get("bf_target_url", ""),
        bf_method=bf.get("bf_method", "GET"),
        bf_fuzz_param=bf.get("bf_fuzz_param", "password"),
        bf_target_param=bf.get("bf_target_param", ""),
        bf_username_param=bf.get("bf_username_param", "username"),
        bf_username=bf.get("bf_username", "admin"),
        bf_extra_params=list(bf.get("bf_extra_params") or []),
        sqli_evasion_level=level,
        sqli_time_based=bool(sqli.get("include_time_based", False)),
        sqli_time_max=int(sqli.get("max_time_payloads", 0)),
        target_dbms=sqli.get("target_dbms", "all"),
        osci_evasion_level=int(osci.get("evasion_level", level)),
        osci_time_based=bool(osci.get("include_time_based", False)),
        osci_time_max=int(osci.get("max_time_payloads", 0)),
        target_os=osci.get("target_os", "linux"),
        lfi_evasion_level=level,
        ssrf_evasion_level=min(level, 2),
        ssrf_oob=bool(ssrf.get("ssrf_include_oob", False)),
        sxss_evasion_level=level,
        sxss_scan_mode=sxss.get("scan_mode", "full"),
        sxss_max_risk_level=sxss.get("max_risk_level", "Critical"),
        sxss_categories=list(sxss.get("categories") or []),
        sxss_target_params=list(sxss.get("target_params") or []),
        rxss_evasion_level=int(rxss.get("evasion_level", 1)),
        oob_server=normalize_oast_server_url(oob_server_raw),
        oob_retries=int(oob.get("oob_retries", 3)),
        oob_poll_delay=float(oob.get("oob_poll_delay", 5.0)),
        oob_poll_timeout=float(oob.get("oob_poll_timeout", 10.0)),
    )


def _serialize_findings(findings) -> list[dict]:
    from reporter.generator import _finding_sort_key

    result: list[dict] = []
    for finding in sorted(findings, key=_finding_sort_key):
        payload_obj = finding.payload
        severity = str(getattr(payload_obj, "risk_level", "HIGH"))
        attack_type = str(getattr(payload_obj, "attack_type", finding.module_name or "Unknown"))
        payload_value = str(getattr(payload_obj, "value", payload_obj))
        param_location = getattr(finding.surface, "param_location", "unknown")
        location_text = str(getattr(param_location, "name", param_location))
        result.append({
            "severity": severity,
            "location": location_text,
            "parameter": str(finding.parameter),
            "url": str(getattr(finding.surface, "url", "") or ""),
            "type": attack_type,
            "payload": payload_value,
        })
    return result


SCAN_LOG_EVERY_COMPLETED_BF_TRUE_RANDOM = 1000


async def _async_run_scan(scan_id: str, request_payload: dict) -> None:
    """실제 asyncio 스캔 엔진 실행 (Celery 워커에서 호출)"""
    from cli.options import parse_cookies
    from cli.runner import prepare_scan_context
    from cli.surfaces import resolve_surfaces
    from fuzzer import FuzzerEngine
    from fuzzer.request_builder import build_and_send_request
    from reporter import ReportGenerator

    started_at = time.monotonic()
    update_scan_fields(scan_id, status="running")
    args = _build_args_from_payload(request_payload)
    target_url = args.url
    scan_type = args.type

    append_scan_log(scan_id, f"[Celery] 스캔 시작: target={target_url}, type={scan_type}")

    if args.type == "oob":
        append_scan_log(scan_id, f"OAST 서버: {args.oob_server}")

    cookies = parse_cookies(args.cookie) if args.cookie else {}
    append_scan_log(scan_id, "공격면 수집 시작")
    surfaces = await resolve_surfaces(args, base_url=args.url, cookies=cookies)
    if not surfaces:
        raise RuntimeError("No attack surfaces resolved from target.")
    append_scan_log(scan_id, f"공격면 수집 완료: {len(surfaces)}개")

    context = prepare_scan_context(args, surfaces)
    if context is None:
        raise RuntimeError("Scan context preparation failed.")
    append_scan_log(
        scan_id,
        f"스캔 컨텍스트 구성 완료 (modules={len(context['modules'])}, total_requests={context['total_requests']})",
    )

    engine = FuzzerEngine(
        max_concurrent_requests=context["concurrency"],
        worker_count=context["queue_workers"],
        modules=context["modules"],
        concurrency_per_module=context["queue_workers"],
        session_pool_size=max(1, args.session_pool_size),
        delay=context["delay"],
    )

    async def _request_sender(session, surface, parameter, payload, allow_redirects=True):
        return await build_and_send_request(
            session, surface, parameter, payload, allow_redirects=allow_redirects
        )

    total_requests = max(1, context["total_requests"])
    update_scan_fields(scan_id, total_requests=total_requests)

    last_logged_progress = -1.0
    bf_true_random_milestone_logs = args.type == "bruteforce" and bool(getattr(args, "bf_true_random", False))
    next_milestone = SCAN_LOG_EVERY_COMPLETED_BF_TRUE_RANDOM if bf_true_random_milestone_logs else 0

    scan_task = asyncio.create_task(
        engine.run_with_attack_modules(surfaces=surfaces, request_sender=_request_sender)
    )

    while not scan_task.done():
        queued_total = engine.stats.queued
        effective_total = max(total_requests, queued_total, 1)
        completed = engine.stats.completed
        progress_pct = min(100.0, round(completed / effective_total * 100, 1))
        if not scan_task.done() and progress_pct >= 99.9:
            progress_pct = 99.9

        summary = {
            "queued": queued_total,
            "completed": completed,
            "failures": engine.stats.failures,
            "findings": engine.stats.findings,
            "elapsed_time": round(time.monotonic() - started_at, 2),
            "total_requests": effective_total,
            "planned_requests": total_requests,
        }
        update_scan_fields(
            scan_id,
            progress_percent=progress_pct,
            progress=int(progress_pct),
            summary=summary,
        )

        if progress_pct != last_logged_progress:
            append_scan_log(
                scan_id,
                f"진행률 {progress_pct}% (completed={engine.stats.completed}, "
                f"findings={engine.stats.findings}, failures={engine.stats.failures})",
            )
            last_logged_progress = progress_pct

        if bf_true_random_milestone_logs:
            while engine.stats.completed >= next_milestone:
                append_scan_log(
                    scan_id,
                    f"[true-random BF] 누적 완료 {next_milestone}건 "
                    f"(queued={engine.stats.queued}, findings={engine.stats.findings})",
                )
                next_milestone += SCAN_LOG_EVERY_COMPLETED_BF_TRUE_RANDOM

        await asyncio.sleep(0.3)

    stats = await scan_task
    reporter = ReportGenerator(stats=stats, findings=engine.findings)
    reporter.export_to_json(args.output)
    append_scan_log(scan_id, f"리포트 파일 저장: {args.output}")

    report_json = None
    try:
        with open(args.output, "r", encoding="utf-8") as fp:
            report_json = json.load(fp)
    except (OSError, json.JSONDecodeError) as exc:
        append_scan_log(scan_id, f"리포트 JSON 로드 실패: {exc}")

    findings = _serialize_findings(engine.findings)
    final_total = max(total_requests, stats.queued, stats.completed, 1)
    update_scan_fields(
        scan_id,
        status="completed",
        progress=100,
        progress_percent=100.0,
        summary={
            "queued": stats.queued,
            "completed": stats.completed,
            "failures": stats.failures,
            "findings": stats.findings,
            "elapsed_time": round(time.monotonic() - started_at, 2),
            "total_requests": final_total,
            "planned_requests": total_requests,
        },
        result={
            "summary": {
                "target": args.url,
                "scan_type": args.type,
                "total_requests": stats.completed,
                "findings": len(findings),
                "output": args.output,
            }
        },
        report_json=report_json,
        error=None,
    )

    scan_pk = get_scan_pk(scan_id)
    if scan_pk is not None:
        replace_scan_findings(scan_pk, findings)

    append_scan_log(scan_id, "[Celery] 스캔 완료")


class _ScanTask(Task):
    """좀비 태스크 방지: 예외로 죽은 경우 DB 상태를 'failed'로 안전하게 저장"""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        scan_id: str = args[0] if args else kwargs.get("scan_id", "")
        if not scan_id:
            return
        scan_row = get_scan_by_public_id(scan_id)
        prev = (scan_row.summary if scan_row else None) or {}
        update_scan_fields(
            scan_id,
            status="failed",
            progress=int((scan_row.progress_percent if scan_row else 0) or 0),
            error=f"[Celery] {exc}",
            summary={
                "queued": prev.get("queued", 0),
                "completed": prev.get("completed", 0),
                "failures": prev.get("failures", 0),
                "findings": prev.get("findings", 0),
                "elapsed_time": prev.get("elapsed_time", 0),
                "total_requests": scan_row.total_requests if scan_row else None,
            },
        )
        append_scan_log(scan_id, f"[Celery] 태스크 실패: {exc}")


@celery_app.task(
    bind=True,
    base=_ScanTask,
    name="webapp.tasks.run_scan",
    max_retries=0,       # 스캔은 자동 재시도 안 함 (데이터 오염 방지)
    time_limit=7200,     # 최대 2시간 초과 시 강제 종료
    soft_time_limit=6900,
)
def run_scan(self, scan_id: str, request_payload: dict) -> str:
    """
    Celery 워커에서 실제 스캔을 실행하는 태스크.
    asyncio 기반 엔진을 새 이벤트 루프에서 실행한다.
    """
    try:
        asyncio.run(_async_run_scan(scan_id, request_payload))
        return f"completed:{scan_id}"
    except Exception as exc:
        # on_failure 콜백이 DB 정리를 담당하므로 여기서는 re-raise만
        raise exc
