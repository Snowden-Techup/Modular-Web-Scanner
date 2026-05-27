from __future__ import annotations

from argparse import Namespace
import asyncio
import json
import time
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from cli.options import parse_bf_length, parse_cookies
from cli.runner import prepare_scan_context
from cli.surfaces import resolve_surfaces
from fuzzer import FuzzerEngine
from fuzzer.request_builder import build_and_send_request
from reporter import ReportGenerator
from modules.oob.client import DEFAULT_OAST_SERVER_URL, normalize_oast_server_url
from reporter.generator import _finding_sort_key

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

SCAN_TYPES = [
    "all",
    "sqli",
    "osci",
    "bruteforce",
    "lfi",
    "file_upload",
    "ssrf",
    "stored_xss",
    "reflected_xss",
    "oob",
]

# Web UI: true-random bruteforce는 total_requests 대비 진행률이 오래 안 바뀌는 경우가 있어
# 이 모드에서만 N건 단위 보조 로그를 남긴다. (그 외는 진행률% 변경 시만 로그)
SCAN_LOG_EVERY_COMPLETED_BF_TRUE_RANDOM = 1000


class AuthSettings(BaseModel):
    login_url: str = ""
    cookie: str = ""
    username: str = ""
    password: str = ""
    username_field: str = "username"
    password_field: str = "password"
    csrf_field: str = "user_token"
    submit_field: str = "Login"


class EngineOptions(BaseModel):
    rps: int = Field(default=50, ge=1, le=10000)
    session_pool_size: int = Field(default=3, ge=1, le=100)
    output: str = "scan_report.json"
    surfaces_output: str = "attack_surfaces.json"


class SQLiOptions(BaseModel):
    include_time_based: bool = False
    max_time_payloads: int = Field(default=0, ge=0)
    target_dbms: Literal["mysql", "mssql", "oracle", "postgres", "sqlite", "access", "all"] = "all"


class OSCiOptions(BaseModel):
    evasion_level: int = Field(default=1, ge=0, le=3)
    include_time_based: bool = False
    max_time_payloads: int = Field(default=0, ge=0)
    target_os: Literal["linux", "windows", "all"] = "linux"


class BruteforceOptions(BaseModel):
    bf_wordlist: str = "config/payloads/bruteforce/common_passwords.txt"
    bf_disable_mutation: bool = False
    bf_mutation_level: int = Field(default=1, ge=0, le=3)
    bf_true_random: bool = False
    bf_charset: str = "abcdefghijklmnopqrstuvwxyz0123456789"
    bf_min_length: int = Field(default=1, ge=1)
    bf_max_length: int = Field(default=3, ge=1)
    bf_length: str = ""
    bf_max_dictionary: int = Field(default=0, ge=0)
    bf_max_true_random: int = Field(default=0, ge=0)
    bf_stop_on_first_hit: bool = True
    bf_target_url: str = ""
    bf_method: Literal["GET", "POST"] = "GET"
    bf_fuzz_param: str = "password"
    bf_target_param: str = ""
    bf_username_param: str = "username"
    bf_username: str = "admin"
    bf_extra_params: list[str] = Field(default_factory=list)


class SSRFOptions(BaseModel):
    ssrf_include_oob: bool = False


class StoredXSSOptions(BaseModel):
    scan_mode: Literal["quick", "full", "stealth"] = "full"
    max_risk_level: Literal["Low", "Medium", "High", "Critical"] = "Critical"
    categories: list[str] = Field(default_factory=list)
    target_params: list[str] = Field(default_factory=list)


class ReflectedXSSOptions(BaseModel):
    evasion_level: int = Field(default=1, ge=0, le=3)


class OOBOptions(BaseModel):
    oob_server: str = Field(
        default=DEFAULT_OAST_SERVER_URL,
        description="Standalone OAST server base URL",
    )
    oob_retries: int = Field(default=3, ge=1, le=20)
    oob_poll_delay: float = Field(default=5.0, ge=1.0, le=120.0)
    oob_poll_timeout: float = Field(default=10.0, ge=1.0, le=60.0)


class ScanRequest(BaseModel):
    target_url: str = Field(..., min_length=1, max_length=2048, alias="url")
    scan_type: Literal[
        "all",
        "sqli",
        "osci",
        "bruteforce",
        "lfi",
        "file_upload",
        "ssrf",
        "stored_xss",
        "reflected_xss",
        "oob",
    ] = "all"
    level: int = Field(default=1, ge=0, le=3)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    engine: EngineOptions = Field(default_factory=EngineOptions)
    sqli: SQLiOptions = Field(default_factory=SQLiOptions)
    osci: OSCiOptions = Field(default_factory=OSCiOptions)
    bruteforce: BruteforceOptions = Field(default_factory=BruteforceOptions)
    ssrf: SSRFOptions = Field(default_factory=SSRFOptions)
    stored_xss: StoredXSSOptions = Field(default_factory=StoredXSSOptions)
    reflected_xss: ReflectedXSSOptions = Field(default_factory=ReflectedXSSOptions)
    oob: OOBOptions = Field(default_factory=OOBOptions)

    model_config = {"populate_by_name": True}


app = FastAPI(
    title="Modular Web Scanner API",
    description="Web UI backend connected to the real CLI scan pipeline.",
    version="0.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

scans_db: dict[str, dict] = {}


@app.get("/api/schema")
async def get_schema() -> dict:
    from modules.stored_xss.payloads import get_all_categories

    return {
        "scan_types": SCAN_TYPES,
        "sxss_categories": get_all_categories(),
        "defaults": {
            "rps": 50,
            "session_pool_size": 3,
            "level": 1,
            "bf_mutation_level": 1,
            "bf_method": "GET",
            "sxss_scan_mode": "full",
            "sxss_max_risk_level": "Critical",
            "osci_evasion_level": 1,
            "rxss_evasion_level": 1,
            "oob_server": DEFAULT_OAST_SERVER_URL,
            "oob_retries": 3,
            "oob_poll_delay": 5.0,
            "oob_poll_timeout": 10.0,
        },
    }


@app.post("/api/scan/start")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks) -> dict:
    scan_id = str(uuid4())
    now = time.time()
    scans_db[scan_id] = {
        "scan_id": scan_id,
        "status": "queued",
        "progress": 0,
        "progress_percent": 0.0,
        "created_at": now,
        "updated_at": now,
        "request": req.model_dump(by_alias=True),
        "target": req.target_url,
        "findings": [],
        "summary": {
            "queued": 0,
            "completed": 0,
            "failures": 0,
            "findings": 0,
            "elapsed_time": 0.0,
        },
        "logs": [],
        "report_json": None,
        "result": None,
        "total_requests": None,
        "progress_percent": 0.0,
    }
    background_tasks.add_task(_run_real_scan, scan_id, req)
    return {
        "status": "accepted",
        "message": "Scan registered in queue.",
        "scan_id": scan_id,
        "request": req.model_dump(by_alias=True),
    }


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    scan = scans_db.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return scan


def _build_cli_args(req: ScanRequest) -> Namespace:
    bf_min_length = req.bruteforce.bf_min_length
    bf_max_length = req.bruteforce.bf_max_length
    if req.bruteforce.bf_length.strip():
        bf_min_length, bf_max_length = parse_bf_length(
            req.bruteforce.bf_length,
            req.bruteforce.bf_max_length,
        )

    level = req.level
    sqli_evasion_level = level
    osci_evasion_level = req.osci.evasion_level
    lfi_evasion_level = level
    ssrf_evasion_level = min(level, 2)
    sxss_evasion_level = level
    rxss_evasion_level = req.reflected_xss.evasion_level

    return Namespace(
        # Core scan options
        url=req.target_url,
        rps=req.engine.rps,
        cookie=req.auth.cookie,
        login_url=req.auth.login_url,
        username=req.auth.username,
        password=req.auth.password,
        username_field=req.auth.username_field,
        password_field=req.auth.password_field,
        csrf_field=req.auth.csrf_field,
        submit_field=req.auth.submit_field,
        output=req.engine.output,
        surfaces_output=req.engine.surfaces_output,
        type=req.scan_type,
        session_pool_size=req.engine.session_pool_size,
        level=level,
        # Bruteforce options
        bf_wordlist=req.bruteforce.bf_wordlist,
        bf_disable_mutation=req.bruteforce.bf_disable_mutation,
        bf_mutation_level=req.bruteforce.bf_mutation_level,
        bf_true_random=req.bruteforce.bf_true_random,
        bf_charset=req.bruteforce.bf_charset,
        bf_min_length=bf_min_length,
        bf_max_length=bf_max_length,
        bf_length=req.bruteforce.bf_length,
        bf_max_dictionary=req.bruteforce.bf_max_dictionary,
        bf_max_true_random=req.bruteforce.bf_max_true_random,
        bf_stop_on_first_hit=req.bruteforce.bf_stop_on_first_hit,
        bf_target_url=req.bruteforce.bf_target_url,
        bf_method=req.bruteforce.bf_method,
        bf_fuzz_param=req.bruteforce.bf_fuzz_param,
        bf_target_param=req.bruteforce.bf_target_param,
        bf_username_param=req.bruteforce.bf_username_param,
        bf_username=req.bruteforce.bf_username,
        bf_extra_params=req.bruteforce.bf_extra_params,
        # SQLi / OSCi / LFI / SSRF (names aligned with cli.parser / fuzzer.setup)
        sqli_evasion_level=sqli_evasion_level,
        sqli_time_based=req.sqli.include_time_based,
        sqli_time_max=req.sqli.max_time_payloads,
        target_dbms=req.sqli.target_dbms,
        osci_evasion_level=osci_evasion_level,
        osci_time_based=req.osci.include_time_based,
        osci_time_max=req.osci.max_time_payloads,
        target_os=req.osci.target_os,
        lfi_evasion_level=lfi_evasion_level,
        ssrf_evasion_level=ssrf_evasion_level,
        ssrf_oob=req.ssrf.ssrf_include_oob,
        sxss_evasion_level=sxss_evasion_level,
        sxss_scan_mode=req.stored_xss.scan_mode,
        sxss_max_risk_level=req.stored_xss.max_risk_level,
        sxss_categories=list(req.stored_xss.categories),
        sxss_target_params=list(req.stored_xss.target_params),
        rxss_evasion_level=rxss_evasion_level,
        # OOB / OAST (standalone callback detection)
        oob_server=normalize_oast_server_url(req.oob.oob_server),
        oob_retries=req.oob.oob_retries,
        oob_poll_delay=req.oob.oob_poll_delay,
        oob_poll_timeout=req.oob.oob_poll_timeout,
    )


def _serialize_findings(findings) -> list[dict[str, str]]:
    serialized: list[dict[str, str]] = []
    for finding in sorted(findings, key=_finding_sort_key):
        payload_obj = finding.payload
        severity = str(getattr(payload_obj, "risk_level", "HIGH"))
        attack_type = str(
            getattr(payload_obj, "attack_type", finding.module_name or "Unknown")
        )
        payload_value = str(getattr(payload_obj, "value", payload_obj))
        param_location = getattr(finding.surface, "param_location", "unknown")
        location_text = str(getattr(param_location, "name", param_location))

        serialized.append(
            {
                "severity": severity,
                "location": location_text,
                "parameter": str(finding.parameter),
                "url": str(getattr(finding.surface, "url", "") or ""),
                "type": attack_type,
                "payload": payload_value,
            }
        )
    return serialized


def _scan_log(scan: dict, message: str) -> None:
    scan.setdefault("logs", []).append(f"[{time.strftime('%H:%M:%S')}] {message}")


async def _run_real_scan(scan_id: str, req: ScanRequest) -> None:
    started_at = time.monotonic()
    scan = scans_db.get(scan_id)
    if scan is None:
        return

    scan["status"] = "running"
    scan["updated_at"] = time.time()
    _scan_log(scan, f"스캔 시작: target={req.target_url}, type={req.scan_type}")

    try:
        args = _build_cli_args(req)
        if args.type == "oob":
            _scan_log(scan, f"OAST 서버: {args.oob_server}")
        _scan_log(scan, "CLI 인자 구성 완료")
        cookies = parse_cookies(args.cookie) if args.cookie else {}
        _scan_log(scan, "공격면 수집 시작")
        surfaces = await resolve_surfaces(args, base_url=args.url, cookies=cookies)
        if not surfaces:
            raise RuntimeError("No attack surfaces resolved from target.")
        _scan_log(scan, f"공격면 수집 완료: {len(surfaces)}개")

        context = prepare_scan_context(args, surfaces)
        if context is None:
            raise RuntimeError("Scan context preparation failed.")
        _scan_log(
            scan,
            "스캔 컨텍스트 구성 완료 "
            f"(modules={len(context['modules'])}, total_requests={context['total_requests']})",
        )

        engine = FuzzerEngine(
            max_concurrent_requests=context["concurrency"],
            worker_count=context["queue_workers"],
            modules=context["modules"],
            concurrency_per_module=context["queue_workers"],
            session_pool_size=max(1, args.session_pool_size),
            delay=context["delay"],
        )

        async def _request_sender(session, surface, parameter, payload):
            return await build_and_send_request(session, surface, parameter, payload)

        total_requests = max(1, context["total_requests"])
        scan["total_requests"] = total_requests
        last_logged_progress = -1.0
        bf_true_random_milestone_logs = args.type == "bruteforce" and bool(
            getattr(args, "bf_true_random", False)
        )
        next_completed_log_milestone = (
            SCAN_LOG_EVERY_COMPLETED_BF_TRUE_RANDOM if bf_true_random_milestone_logs else 0
        )
        scan_task = asyncio.create_task(
            engine.run_with_attack_modules(
                surfaces=surfaces,
                request_sender=_request_sender,
            )
        )

        while not scan_task.done():
            planned_total = total_requests
            queued_total = engine.stats.queued
            effective_total = max(planned_total, queued_total, 1)
            completed = engine.stats.completed
            progress_pct = min(
                100.0,
                round(completed / effective_total * 100, 1),
            )
            if not scan_task.done() and progress_pct >= 99.9:
                progress_pct = 99.9
            scan["progress_percent"] = progress_pct
            scan["progress"] = int(progress_pct)
            scan["summary"] = {
                "queued": queued_total,
                "completed": completed,
                "failures": engine.stats.failures,
                "findings": engine.stats.findings,
                "elapsed_time": round(time.monotonic() - started_at, 2),
                "total_requests": effective_total,
                "planned_requests": planned_total,
            }
            scan["updated_at"] = time.time()
            if progress_pct != last_logged_progress:
                _scan_log(
                    scan,
                    f"진행률 {progress_pct}% (completed={engine.stats.completed}, findings={engine.stats.findings}, failures={engine.stats.failures})",
                )
                last_logged_progress = progress_pct
            if bf_true_random_milestone_logs:
                completed_now = engine.stats.completed
                while completed_now >= next_completed_log_milestone:
                    _scan_log(
                        scan,
                        f"[true-random BF] 누적 요청 완료 {next_completed_log_milestone}건 "
                        f"(queued={engine.stats.queued}, findings={engine.stats.findings}, failures={engine.stats.failures})",
                    )
                    next_completed_log_milestone += SCAN_LOG_EVERY_COMPLETED_BF_TRUE_RANDOM
            await asyncio.sleep(0.3)

        stats = await scan_task
        reporter = ReportGenerator(stats=stats, findings=engine.findings)
        reporter.export_to_json(args.output)
        _scan_log(scan, f"리포트 파일 저장 완료: {args.output}")

        report_json = None
        try:
            with open(args.output, "r", encoding="utf-8") as fp:
                report_json = json.load(fp)
            _scan_log(scan, "리포트 JSON 로드 완료")
        except (OSError, json.JSONDecodeError) as exc:
            _scan_log(scan, f"리포트 JSON 로드 실패: {exc}")

        findings = _serialize_findings(engine.findings)
        final_total = max(total_requests, stats.queued, stats.completed, 1)
        scan["status"] = "completed"
        scan["progress"] = 100
        scan["progress_percent"] = 100.0
        scan["findings"] = findings
        scan["summary"] = {
            "queued": stats.queued,
            "completed": stats.completed,
            "failures": stats.failures,
            "findings": stats.findings,
            "elapsed_time": round(time.monotonic() - started_at, 2),
            "total_requests": final_total,
            "planned_requests": total_requests,
        }
        scan["result"] = {
            "summary": {
                "target": args.url,
                "scan_type": args.type,
                "total_requests": stats.completed,
                "findings": len(findings),
                "output": args.output,
            }
        }
        scan["report_json"] = report_json
        scan["updated_at"] = time.time()
        _scan_log(scan, "스캔 완료")
    except Exception as exc:
        scan["status"] = "failed"
        scan["progress"] = int(scan.get("progress_percent") or scan.get("progress") or 0)
        scan["error"] = str(exc)
        prev = scan.get("summary") or {}
        scan["summary"] = {
            "queued": prev.get("queued", 0),
            "completed": prev.get("completed", 0),
            "failures": prev.get("failures", 0),
            "findings": prev.get("findings", 0),
            "elapsed_time": round(time.monotonic() - started_at, 2),
            "total_requests": scan.get("total_requests"),
        }
        scan["updated_at"] = time.time()
        _scan_log(scan, f"스캔 실패: {exc}")


@app.get("/")
async def serve_index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
