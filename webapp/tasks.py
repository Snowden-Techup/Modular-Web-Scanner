from __future__ import annotations

import asyncio
import copy
import json
import shutil
import time

from argparse import Namespace
from celery import Task
from pathlib import Path

from webapp.celery_app import celery_app
from webapp.db_service import (
    append_scan_log,
    build_oob_report_json,
    bulk_save_oob_tokens,
    dedupe_finding_dicts,
    findings_from_rows,
    get_scan_by_public_id,
    get_scan_findings_rows,
    get_scan_pk,
    replace_scan_findings,
    update_scan_fields,
)

OOB_WEB_SCAN_TYPES = frozenset({"oob_sqli", "oob_osci"})


# ─────────────────────────────────────────
# 스캔 요청 dict → Namespace (CLI와 동일한 의미; DVWA 기본 CSRF/submit 미적용)
# tasks.py 는 main.py 를 import 하지 않으므로 독립적으로 정의
# ─────────────────────────────────────────
def _blankable_auth_field(auth: dict, key: str) -> str:
    """빈 문자열·공백은 '필드 없음'으로 처리 (CLI --csrf-field \"\" 와 동일)."""
    raw = auth.get(key, "")
    if raw is None:
        return ""
    return str(raw).strip()


def _resolve_login_body_format(auth: dict) -> str:
    if auth.get("login_json"):
        return "json"
    return auth.get("login_body_format") or "auto"


def _apply_spa_runtime_options(args: Namespace, *, on_warning) -> None:
    from fuzzer.request_builder import set_graphql_safe_mode

    if getattr(args, "graphql_unsafe", False):
        if on_warning:
            on_warning(
                "GraphQL unsafe mode: mutations will be attacked; "
                "server/database state may change."
            )
        set_graphql_safe_mode(False)
    else:
        set_graphql_safe_mode(True)
    if getattr(args, "unsafe_click", False) and on_warning:
        on_warning(
            "SPA unsafe click: non-submit UI buttons may be clicked "
            "(higher coverage; logout/session loss risk)."
        )
    if getattr(args, "fuzz_csrf", False) and on_warning:
        on_warning(
            "CSRF fuzzing: dynamic-token surfaces will be attacked "
            "(slower; may invalidate sessions)."
        )
    if getattr(args, "fuzz_auth", False) and on_warning:
        on_warning(
            "Auth endpoint fuzzing: login/token surfaces will be attacked "
            "(may invalidate sessions or lock accounts)."
        )


def _build_args_from_payload(payload: dict) -> Namespace:
    from cli.options import parse_bf_length

    bf = payload.get("bruteforce", {})
    engine = payload.get("engine", {})
    auth = payload.get("auth", {})
    crawler = payload.get("crawler", {})
    sqli = payload.get("sqli", {})
    osci = payload.get("osci", {})
    ssrf = payload.get("ssrf", {})
    sxss = payload.get("stored_xss", {})
    rxss = payload.get("reflected_xss", {})
    ssti = payload.get("ssti", {})

    level = int(payload.get("level", 1))
    bf_min = int(bf.get("bf_min_length", 1))
    bf_max = int(bf.get("bf_max_length", 3))
    bf_length_str = str(bf.get("bf_length", "") or "")
    if bf_length_str.strip():
        try:
            bf_min, bf_max = parse_bf_length(bf_length_str, bf_max)
        except ValueError:
            pass

    raw_url = (payload.get("url") or payload.get("target_url") or "").strip()
    scan_url = raw_url.rstrip("/") if raw_url else ""
    login_body_format = _resolve_login_body_format(auth)
    exclude_urls = list(crawler.get("exclude_urls") or payload.get("exclude_urls") or [])

    return Namespace(
        url=scan_url,
        rps=int(engine.get("rps", 50)),
        workers=0,
        cookie=(auth.get("cookie") or "").strip(),
        login_url=(auth.get("login_url") or "").strip(),
        username=(auth.get("username") or "").strip(),
        password=auth.get("password") or "",
        username_field=auth.get("username_field") or "username",
        password_field=auth.get("password_field") or "password",
        csrf_field=_blankable_auth_field(auth, "csrf_field"),
        submit_field=_blankable_auth_field(auth, "submit_field"),
        login_json=bool(auth.get("login_json", False)),
        login_body_format=login_body_format,
        output=engine.get("output", "scan_report.json"),
        surfaces_output=engine.get("surfaces_output", "attack_surfaces.json"),
        type=payload.get("scan_type") or payload.get("type") or "all",
        session_pool_size=int(engine.get("session_pool_size", 3)),
        level=level,
        crawl_mode=crawler.get("crawl_mode", "static"),
        spa_max_routes=int(crawler.get("spa_max_routes", 50)),
        local_storage=crawler.get("local_storage", "{}"),
        unsafe_click=bool(crawler.get("unsafe_click", False)),
        exclude_urls=exclude_urls,
        fuzz_csrf=bool(crawler.get("fuzz_csrf", False)),
        fuzz_auth=bool(crawler.get("fuzz_auth", False)),
        graphql_unsafe=bool(crawler.get("graphql_unsafe", False)),
        exclude_auth_paths=list(crawler.get("exclude_auth_paths") or []),
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
        ssti_evasion_level=level,
        ssti_max_payloads=(
            int(ssti.get("max_payloads"))
            if int(ssti.get("max_payloads", 0) or 0) > 0
            else None
        ),
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
    return dedupe_finding_dicts(result)


def _pipeline_persisted_findings(scan_pk: int | None, all_findings: list) -> list[dict]:
    """Engine findings + OOB webhook rows already in DB (deduped)."""
    combined = _serialize_findings(all_findings)
    if scan_pk is None:
        return combined
    db_flat = findings_from_rows(get_scan_findings_rows(scan_pk))
    return dedupe_finding_dicts(combined + db_flat)


SCAN_LOG_EVERY_COMPLETED_BF_TRUE_RANDOM = 1000
SCAN_REPORT_ARCHIVE_DIR = Path("report")
SCAN_RUNTIME_REPORT_DIR = Path(".scan_reports")
SCAN_REPORT_ARCHIVE_MAX_FILES = 100
# 진행률 DB 동기화 최소 간격(초). 동기 커밋이 asyncio 루프를 막지 않도록 to_thread + 스로틀.
PROGRESS_DB_SYNC_INTERVAL = 1.5


async def _scan_log(scan_id: str, message: str) -> None:
    await asyncio.to_thread(append_scan_log, scan_id, message)


async def _scan_update(scan_id: str, **fields) -> None:
    await asyncio.to_thread(update_scan_fields, scan_id, **fields)


def _persist_pipeline_partial_report(
    scan_id: str,
    *,
    runtime_output: Path,
    all_findings: list,
    merged_stats,
    summary: dict,
    pipeline_has_oob: bool = False,
) -> None:
    """모듈 완료 직후 누적 리포트를 파일·DB에 반영 (다음 모듈 시작 전)."""
    from reporter import ReportGenerator

    scan_pk = get_scan_pk(scan_id)
    combined = _pipeline_persisted_findings(scan_pk, all_findings)
    if scan_pk is not None:
        replace_scan_findings(scan_pk, combined)

    reporter = ReportGenerator(stats=merged_stats, findings=all_findings)
    if pipeline_has_oob and scan_pk is not None:
        scan_row = get_scan_by_public_id(scan_id)
        rows = get_scan_findings_rows(scan_pk)
        report_json = build_oob_report_json(scan_row, rows) if scan_row else reporter.build_deduped_report()
    else:
        report_json = reporter.build_deduped_report()

    reporter.export_to_json(str(runtime_output))
    # Do not touch progress fields here — concurrent poll loop may have advanced them.
    update_scan_fields(scan_id, report_json=report_json, summary=summary)


async def _flush_pipeline_partial_report(
    scan_id: str,
    *,
    runtime_output: Path,
    all_findings: list,
    merged_stats,
    summary: dict,
    module_type: str,
    module_run_idx: int,
    n_modules: int,
    pipeline_has_oob: bool = False,
) -> None:
    await asyncio.to_thread(
        _persist_pipeline_partial_report,
        scan_id,
        runtime_output=runtime_output,
        all_findings=all_findings,
        merged_stats=merged_stats,
        summary=summary,
        pipeline_has_oob=pipeline_has_oob,
    )
    await _scan_log(
        scan_id,
        f"[Pipeline] 누적 리포트 갱신 ({module_run_idx}/{n_modules} {module_type} 완료, "
        f"findings={merged_stats.findings})",
    )


def _runtime_scan_report_path(scan_id: str) -> Path:
    return SCAN_RUNTIME_REPORT_DIR / scan_id / "scan_report.json"


def _archive_scan_report_path(scan_id: str) -> Path:
    return SCAN_REPORT_ARCHIVE_DIR / f"scan_report_{scan_id}.json"


def _prune_report_archive(max_files: int = SCAN_REPORT_ARCHIVE_MAX_FILES) -> None:
    report_files = sorted(
        SCAN_REPORT_ARCHIVE_DIR.glob("scan_report_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for old_file in report_files[max_files:]:
        try:
            old_file.unlink()
        except OSError:
            continue


async def _async_run_scan_pipeline(
    scan_id: str,
    args,
    surfaces: list,
    cookies: dict,
    started_at: float,
    runtime_output: Path,
) -> None:
    """
    -t all 전용 순차 파이프라인.

    모듈을 하나씩 실행하고 각 완료 후 중간 리포트를 저장한다.
    전체 완료 후 최종 합산 리포트를 저장하고 DB를 완료 상태로 갱신한다.
    """
    from cli.runner import prepare_scan_context
    from fuzzer import EngineStats, FuzzerEngine
    from fuzzer.auth_provider import scan_auth_lifecycle
    from fuzzer.request_builder import build_and_send_request
    from fuzzer.setup import estimate_total_requests, pipeline_module_types, select_modules
    from reporter import ReportGenerator
    from reporter.dedupe import full_report_path

    # ── 1. 전체 예상 요청 수 사전 계산 (진행바 분모) ─────────────────────────
    pipeline_types = pipeline_module_types(args)
    pipeline_has_oob = bool(set(pipeline_types) & OOB_WEB_SCAN_TYPES)
    module_totals: dict[str, int] = {}
    for mtype in pipeline_types:
        mod_args = copy.copy(args)
        mod_args.type = mtype
        mods = select_modules(mod_args)
        if mods:
            module_totals[mtype] = estimate_total_requests(surfaces, mods)
    overall_total = max(1, sum(module_totals.values()))
    n_modules = len([t for t in pipeline_types if module_totals.get(t, 0) > 0])

    await _scan_update(
        scan_id,
        total_requests=overall_total,
        progress=0,
        progress_percent=0.0,
        summary={
            "phase": "fuzzing",
            "current_module": "",
            "module_index": 0,
            "module_count": n_modules,
            "queued": 0,
            "observed_total": 0,
            "completed": 0,
            "failures": 0,
            "findings": 0,
            "elapsed_time": round(time.monotonic() - started_at, 2),
            "total_requests": overall_total,
            "planned_requests": overall_total,
        },
    )

    async def _request_sender(session, surface, parameter, payload, allow_redirects=True):
        return await build_and_send_request(session, surface, parameter, payload, allow_redirects=allow_redirects)

    # ── 2. 모듈별 순차 실행 ───────────────────────────────────────────────────
    all_findings: list = []
    all_pipeline_modules: list = []
    merged_stats = EngineStats(queued=0, completed=0, failures=0, findings=0)
    cumulative_completed = 0
    cumulative_findings = 0
    last_shown_progress = 0.0
    last_logged_progress = -1.0
    last_db_sync_at = 0.0
    module_run_idx = 0

    async with scan_auth_lifecycle(args, base_cookies=cookies):
        for module_type in pipeline_types:
            if module_totals.get(module_type, 0) == 0:
                continue

            module_run_idx += 1
            mod_args = copy.copy(args)
            mod_args.type = module_type

            context = prepare_scan_context(mod_args, surfaces)
            if context is None:
                await _scan_log(scan_id, f"[Pipeline] {module_type}: 컨텍스트 준비 실패, 건너뜀")
                continue

            module_total = context["total_requests"]
            await _scan_log(
                scan_id,
                f"[Pipeline {module_run_idx}/{n_modules}] {module_type} 시작 "
                f"(예상 {module_total}건)",
            )
            await _scan_update(
                scan_id,
                progress_percent=last_shown_progress,
                progress=int(last_shown_progress),
                summary={
                    "phase": "fuzzing",
                    "current_module": module_type,
                    "module_index": module_run_idx,
                    "module_count": n_modules,
                    "queued": 0,
                    "observed_total": max(overall_total, cumulative_completed, 1),
                    "completed": cumulative_completed,
                    "failures": merged_stats.failures,
                    "findings": cumulative_findings,
                    "elapsed_time": round(time.monotonic() - started_at, 2),
                    "total_requests": overall_total,
                    "planned_requests": overall_total,
                },
            )

            engine = FuzzerEngine(
                max_concurrent_requests=context["concurrency"],
                worker_count=context["queue_workers"],
                modules=context["modules"],
                concurrency_per_module=context["queue_workers"],
                session_pool_size=max(1, args.session_pool_size),
                delay=context["delay"],
            )

            scan_task = asyncio.create_task(
                engine.run_with_attack_modules(surfaces=surfaces, request_sender=_request_sender)
            )

            while not scan_task.done():
                current_completed = cumulative_completed + engine.stats.completed
                observed_total = max(
                    overall_total,
                    cumulative_completed + engine.stats.queued,
                    current_completed,
                    1,
                )
                # Fixed planned denominator — growing queued must not shrink the percentage.
                raw_pct = min(100.0, round(current_completed / overall_total * 100, 1))
                if not scan_task.done() and raw_pct >= 99.9:
                    raw_pct = 99.9
                progress_pct = max(last_shown_progress, raw_pct)
                last_shown_progress = progress_pct

                findings_count = cumulative_findings + engine.stats.findings
                if module_type in OOB_WEB_SCAN_TYPES:
                    scan_row = await asyncio.to_thread(get_scan_by_public_id, scan_id)
                    if scan_row and scan_row.summary:
                        findings_count = int(scan_row.summary.get("findings", findings_count))

                summary = {
                    "phase": "fuzzing",
                    "current_module": module_type,
                    "module_index": module_run_idx,
                    "module_count": n_modules,
                    "queued": engine.stats.queued,
                    "observed_total": observed_total,
                    "completed": current_completed,
                    "failures": merged_stats.failures + engine.stats.failures,
                    "findings": findings_count,
                    "elapsed_time": round(time.monotonic() - started_at, 2),
                    "total_requests": overall_total,
                    "planned_requests": overall_total,
                }

                now = time.monotonic()
                progress_changed = progress_pct != last_logged_progress
                if progress_changed or (now - last_db_sync_at) >= PROGRESS_DB_SYNC_INTERVAL:
                    await _scan_update(
                        scan_id,
                        progress_percent=progress_pct,
                        progress=int(progress_pct),
                        summary=summary,
                    )
                    last_db_sync_at = now

                if progress_changed:
                    await _scan_log(
                        scan_id,
                        f"[{module_type}] 진행률 {progress_pct}% "
                        f"(completed={engine.stats.completed}, findings={engine.stats.findings})",
                    )
                    last_logged_progress = progress_pct

                await asyncio.sleep(0.3)

            stats = await scan_task

            cumulative_completed += stats.completed
            observed_total = max(
                overall_total,
                cumulative_completed,
                cumulative_completed + stats.queued,
                1,
            )
            module_end_pct = min(100.0, round(cumulative_completed / overall_total * 100, 1))
            last_shown_progress = max(last_shown_progress, module_end_pct)
            await _scan_update(
                scan_id,
                progress_percent=last_shown_progress,
                progress=int(last_shown_progress),
            )

            # 모듈별 중간 리포트 저장
            module_output = runtime_output.with_name(
                f"{runtime_output.stem}_{module_type}{runtime_output.suffix}"
            )
            module_reporter = ReportGenerator(stats=stats, findings=engine.findings)
            await asyncio.to_thread(module_reporter.export_to_json, str(module_output))
            await _scan_log(
                scan_id,
                f"[Pipeline {module_run_idx}/{n_modules}] {module_type} 완료 "
                f"(findings={stats.findings}, report={module_output.name})",
            )

            all_findings.extend(engine.findings)
            all_pipeline_modules.extend(context["modules"])
            if module_type in OOB_WEB_SCAN_TYPES:
                scan_row = await asyncio.to_thread(get_scan_by_public_id, scan_id)
                cumulative_findings = int((scan_row.summary or {}).get("findings", cumulative_findings))
            else:
                cumulative_findings += stats.findings
            merged_stats.queued += stats.queued
            merged_stats.completed += stats.completed
            merged_stats.failures += stats.failures
            merged_stats.findings = cumulative_findings

            partial_summary = {
                "phase": "fuzzing",
                "current_module": module_type,
                "module_index": module_run_idx,
                "module_count": n_modules,
                "queued": stats.queued,
                "observed_total": observed_total,
                "completed": cumulative_completed,
                "failures": merged_stats.failures,
                "findings": cumulative_findings,
                "elapsed_time": round(time.monotonic() - started_at, 2),
                "total_requests": overall_total,
                "planned_requests": overall_total,
            }
            await _flush_pipeline_partial_report(
                scan_id,
                runtime_output=runtime_output,
                all_findings=all_findings,
                merged_stats=merged_stats,
                summary=partial_summary,
                module_type=module_type,
                module_run_idx=module_run_idx,
                n_modules=n_modules,
                pipeline_has_oob=pipeline_has_oob,
            )

    # ── 3. 최종 합산 리포트 저장 ──────────────────────────────────────────────
    final_reporter = ReportGenerator(stats=merged_stats, findings=all_findings)
    await asyncio.to_thread(final_reporter.export_to_json, args.output)
    await _scan_log(scan_id, f"[Pipeline] 최종 합산 리포트 저장: {args.output}")

    archived_output = _archive_scan_report_path(scan_id)
    archived_output.parent.mkdir(parents=True, exist_ok=True)
    runtime_full = full_report_path(runtime_output)
    debug_output = Path("scan_report.json")
    debug_full = full_report_path(debug_output)

    try:
        await asyncio.to_thread(shutil.copy2, runtime_output, archived_output)
        await asyncio.to_thread(_prune_report_archive)
    except OSError as exc:
        await _scan_log(scan_id, f"report 디렉터리 저장 실패: {exc}")

    try:
        await asyncio.to_thread(shutil.copy2, runtime_output, debug_output)
        if runtime_full.exists():
            await asyncio.to_thread(shutil.copy2, runtime_full, debug_full)
    except OSError as exc:
        await _scan_log(scan_id, f"디버깅 리포트 갱신 실패: {exc}")

    report_json = None
    try:
        def _load_report() -> dict:
            with open(archived_output, "r", encoding="utf-8") as fp:
                return json.load(fp)
        report_json = await asyncio.to_thread(_load_report)
    except (OSError, json.JSONDecodeError) as exc:
        await _scan_log(scan_id, f"리포트 JSON 로드 실패: {exc}")

    findings = _pipeline_persisted_findings(
        await asyncio.to_thread(get_scan_pk, scan_id),
        all_findings,
    )
    merged_stats.findings = len(findings)
    if pipeline_has_oob:
        scan_pk = await asyncio.to_thread(get_scan_pk, scan_id)
        if scan_pk is not None:
            def _build_pipeline_oob_report() -> dict:
                scan_row = get_scan_by_public_id(scan_id)
                if scan_row is None:
                    return {}
                rows = get_scan_findings_rows(scan_pk)
                return build_oob_report_json(scan_row, rows)

            report_json = await asyncio.to_thread(_build_pipeline_oob_report)
    final_observed = max(overall_total, merged_stats.queued, merged_stats.completed, 1)
    await _scan_update(
        scan_id,
        status="completed",
        progress=100,
        progress_percent=100.0,
        total_requests=overall_total,
        summary={
            "phase": "completed",
            "module_count": n_modules,
            "queued": merged_stats.queued,
            "observed_total": final_observed,
            "completed": merged_stats.completed,
            "failures": merged_stats.failures,
            "findings": merged_stats.findings,
            "elapsed_time": round(time.monotonic() - started_at, 2),
            "total_requests": overall_total,
            "planned_requests": overall_total,
        },
        result={
            "summary": {
                "target": args.url,
                "scan_type": args.type,
                "total_requests": merged_stats.completed,
                "findings": len(findings),
                "output": str(archived_output),
            }
        },
        report_json=report_json,
        error=None,
    )

    scan_pk = await asyncio.to_thread(get_scan_pk, scan_id)
    if scan_pk is not None:
        await asyncio.to_thread(replace_scan_findings, scan_pk, findings)

    # webhook 모드에서 발급한 OOB 토큰을 DB에 일괄 저장 (Redis TTL 만료 시 fallback용)
    all_issued_tokens = [
        item for m in all_pipeline_modules
        if hasattr(m, "generated_tokens")
        for item in m.generated_tokens
        if item.get("token", "").startswith("w")
    ]
    if all_issued_tokens:
        try:
            inserted = await asyncio.to_thread(bulk_save_oob_tokens, all_issued_tokens)
            await _scan_log(
                scan_id,
                f"[OOB] {inserted}/{len(all_issued_tokens)}개 토큰을 DB에 저장",
            )
        except Exception as exc:
            await _scan_log(
                scan_id,
                f"[OOB] 토큰 DB 저장 실패 (스캔 결과는 유지): {exc}",
            )

    await _scan_log(scan_id, "[Celery/Pipeline] 스캔 완료")


async def _async_run_scan(scan_id: str, request_payload: dict) -> None:
    """실제 asyncio 스캔 엔진 실행 (Celery 워커에서 호출)"""
    from cli.options import parse_cookies
    from cli.runner import prepare_scan_context
    from cli.surfaces import resolve_surfaces
    from fuzzer import FuzzerEngine
    from fuzzer.auth_provider import scan_auth_lifecycle
    from fuzzer.request_builder import build_and_send_request
    from reporter import ReportGenerator

    started_at = time.monotonic()
    await _scan_update(
        scan_id,
        status="running",
        summary={
            "phase": "crawling",
            "queued": 0,
            "completed": 0,
            "failures": 0,
            "findings": 0,
            "elapsed_time": 0.0,
        },
    )
    args = _build_args_from_payload(request_payload)
    args.scan_id = scan_id
    runtime_output = _runtime_scan_report_path(scan_id)
    runtime_output.parent.mkdir(parents=True, exist_ok=True)
    args.output = str(runtime_output)
    args.surfaces_output = str(runtime_output.parent / "attack_surfaces.json")
    target_url = args.url
    scan_type = args.type

    await _scan_log(scan_id, f"[Celery] 스캔 시작: target={target_url}, type={scan_type}")
    _apply_spa_runtime_options(
        args,
        on_warning=lambda msg: append_scan_log(scan_id, f"[WARNING] {msg}"),
    )
    await _scan_log(
        scan_id,
        f"CLI 인자 구성 완료 (crawl_mode={args.crawl_mode}, spa_max_routes={args.spa_max_routes})",
    )
    if args.login_url:
        await _scan_log(
            scan_id,
            "로그인: "
            f"url={args.login_url}, user={args.username_field}, "
            f"csrf={args.csrf_field or '(없음)'}, submit={args.submit_field or '(없음)'}",
        )

    cookies = parse_cookies(args.cookie) if args.cookie else {}
    await _scan_log(scan_id, "공격면 수집 시작")
    surfaces = await resolve_surfaces(args, base_url=args.url, cookies=cookies)
    if not surfaces:
        raise RuntimeError("No attack surfaces resolved from target.")
    await _scan_log(scan_id, f"공격면 수집 완료: {len(surfaces)}개")
    await _scan_update(
        scan_id,
        summary={
            "phase": "fuzzing",
            "surface_count": len(surfaces),
            "elapsed_time": round(time.monotonic() - started_at, 2),
        },
    )

    # -t all: 모듈 순차 파이프라인 실행
    if args.type == "all":
        await _async_run_scan_pipeline(scan_id, args, surfaces, cookies, started_at, runtime_output)
        return

    context = prepare_scan_context(args, surfaces)
    if context is None:
        raise RuntimeError("Scan context preparation failed.")
    await _scan_log(
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
            session,
            surface,
            parameter,
            payload,
            allow_redirects=allow_redirects,
        )

    total_requests = max(1, context["total_requests"])
    await _scan_update(
        scan_id,
        total_requests=total_requests,
        progress=0,
        progress_percent=0.0,
        summary={
            "phase": "fuzzing",
            "queued": 0,
            "observed_total": 0,
            "completed": 0,
            "failures": 0,
            "findings": 0,
            "elapsed_time": round(time.monotonic() - started_at, 2),
            "total_requests": total_requests,
            "planned_requests": total_requests,
        },
    )

    last_logged_progress = -1.0
    last_shown_progress = 0.0
    last_db_sync_at = 0.0
    bf_true_random_milestone_logs = args.type == "bruteforce" and bool(getattr(args, "bf_true_random", False))
    next_milestone = SCAN_LOG_EVERY_COMPLETED_BF_TRUE_RANDOM if bf_true_random_milestone_logs else 0

    async with scan_auth_lifecycle(args, base_cookies=cookies):
        scan_task = asyncio.create_task(
            engine.run_with_attack_modules(surfaces=surfaces, request_sender=_request_sender)
        )

        while not scan_task.done():
            queued_total = engine.stats.queued
            observed_total = max(total_requests, queued_total, engine.stats.completed, 1)
            completed = engine.stats.completed
            raw_progress_pct = min(100.0, round(completed / total_requests * 100, 1))
            if not scan_task.done() and raw_progress_pct >= 99.9:
                raw_progress_pct = 99.9
            progress_pct = max(last_shown_progress, raw_progress_pct)
            last_shown_progress = progress_pct

            findings_count = engine.stats.findings
            if args.type in OOB_WEB_SCAN_TYPES:
                scan_row = await asyncio.to_thread(get_scan_by_public_id, scan_id)
                if scan_row and scan_row.summary:
                    findings_count = int(scan_row.summary.get("findings", findings_count))

            summary = {
                "phase": "fuzzing",
                "queued": queued_total,
                "observed_total": observed_total,
                "completed": completed,
                "failures": engine.stats.failures,
                "findings": findings_count,
                "elapsed_time": round(time.monotonic() - started_at, 2),
                "total_requests": total_requests,
                "planned_requests": total_requests,
            }

            now = time.monotonic()
            progress_changed = progress_pct != last_logged_progress
            if progress_changed or (now - last_db_sync_at) >= PROGRESS_DB_SYNC_INTERVAL:
                await _scan_update(
                    scan_id,
                    progress_percent=progress_pct,
                    progress=int(progress_pct),
                    summary=summary,
                )
                last_db_sync_at = now

            if progress_changed:
                await _scan_log(
                    scan_id,
                    f"진행률 {progress_pct}% (completed={engine.stats.completed}, "
                    f"findings={findings_count}, failures={engine.stats.failures})",
                )
                last_logged_progress = progress_pct

            if bf_true_random_milestone_logs:
                while engine.stats.completed >= next_milestone:
                    await _scan_log(
                        scan_id,
                        f"[true-random BF] 누적 완료 {next_milestone}건 "
                        f"(queued={engine.stats.queued}, findings={engine.stats.findings})",
                    )
                    next_milestone += SCAN_LOG_EVERY_COMPLETED_BF_TRUE_RANDOM

            await asyncio.sleep(0.3)

        stats = await scan_task

    scan_pk = await asyncio.to_thread(get_scan_pk, scan_id)
    is_oob_web_scan = args.type in OOB_WEB_SCAN_TYPES

    if is_oob_web_scan and scan_pk is not None:
        def _build_oob_report() -> dict:
            scan_row = get_scan_by_public_id(scan_id)
            if scan_row is None:
                return {}
            rows = get_scan_findings_rows(scan_pk)
            return build_oob_report_json(scan_row, rows)

        report_json = await asyncio.to_thread(_build_oob_report)

        def _write_report() -> None:
            with open(args.output, "w", encoding="utf-8") as fp:
                json.dump(report_json, fp, ensure_ascii=False, indent=2)

        await asyncio.to_thread(_write_report)
        await _scan_log(scan_id, f"OOB 리포트 파일 저장: {args.output}")
        findings = findings_from_rows(await asyncio.to_thread(get_scan_findings_rows, scan_pk))
        deduped_findings_count = report_json["metadata"]["summary"]["findings_deduped"]
    else:
        reporter = ReportGenerator(stats=stats, findings=engine.findings)
        await asyncio.to_thread(reporter.export_to_json, args.output)
        await _scan_log(scan_id, f"리포트 파일 저장: {args.output}")
        report_json = None
        findings = _serialize_findings(engine.findings)
        deduped_findings_count = len(findings)

    archived_output = _archive_scan_report_path(scan_id)
    archived_output.parent.mkdir(parents=True, exist_ok=True)

    from reporter.dedupe import full_report_path
    runtime_full = full_report_path(runtime_output)
    debug_output = Path("scan_report.json")
    debug_full = full_report_path(debug_output)

    try:
        await asyncio.to_thread(shutil.copy2, runtime_output, archived_output)
        await asyncio.to_thread(_prune_report_archive)
    except OSError as exc:
        await _scan_log(scan_id, f"report 디렉터리 저장 실패: {exc}")

    try:
        # 모듈 디버깅 편의를 위해 최신 결과를 고정 파일명으로도 유지한다.
        await asyncio.to_thread(shutil.copy2, runtime_output, debug_output)
        if runtime_full.exists():
            await asyncio.to_thread(shutil.copy2, runtime_full, debug_full)
    except OSError as exc:
        await _scan_log(scan_id, f"디버깅 리포트 갱신 실패: {exc}")

    if report_json is None:
        try:
            def _load_report() -> dict:
                with open(archived_output, "r", encoding="utf-8") as fp:
                    return json.load(fp)

            report_json = await asyncio.to_thread(_load_report)
        except (OSError, json.JSONDecodeError) as exc:
            await _scan_log(scan_id, f"리포트 JSON 로드 실패: {exc}")

    final_observed = max(total_requests, stats.queued, stats.completed, 1)
    await _scan_update(
        scan_id,
        status="completed",
        progress=100,
        progress_percent=100.0,
        total_requests=total_requests,
        summary={
            "phase": "completed",
            "queued": stats.queued,
            "observed_total": final_observed,
            "completed": stats.completed,
            "failures": stats.failures,
            "findings": deduped_findings_count,
            "elapsed_time": round(time.monotonic() - started_at, 2),
            "total_requests": total_requests,
            "planned_requests": total_requests,
        },
        result={
            "summary": {
                "target": args.url,
                "scan_type": args.type,
                "total_requests": stats.completed,
                "findings": deduped_findings_count,
                "output": str(archived_output),
            }
        },
        report_json=report_json,
        error=None,
    )

    if scan_pk is not None:
        await asyncio.to_thread(replace_scan_findings, scan_pk, findings)

    # webhook 모드에서 발급한 OOB 토큰을 DB에 일괄 저장 (Redis TTL 만료 시 fallback용)
    all_issued_tokens = [
        item for m in context["modules"]
        if hasattr(m, "generated_tokens")
        for item in m.generated_tokens
        if item.get("token", "").startswith("w")
    ]
    if all_issued_tokens:
        try:
            inserted = await asyncio.to_thread(bulk_save_oob_tokens, all_issued_tokens)
            await _scan_log(
                scan_id,
                f"[OOB] {inserted}/{len(all_issued_tokens)}개 토큰을 DB에 저장",
            )
        except Exception as exc:
            await _scan_log(
                scan_id,
                f"[OOB] 토큰 DB 저장 실패 (스캔 결과는 유지): {exc}",
            )

    await _scan_log(scan_id, "[Celery] 스캔 완료")


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