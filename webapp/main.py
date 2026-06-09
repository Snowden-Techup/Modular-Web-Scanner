
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Request
from fastapi import Depends, Header, status
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import jwt

from webapp.celery_app import celery_app  # noqa: F401 — Celery 앱 등록
from webapp.database import get_db, init_db
from webapp.database import SessionLocal
from webapp.db_service import (
    MAX_SCAN_HISTORY_PER_USER,
    findings_from_rows,
    get_oob_token_meta,
    get_scan_by_public_id,
    get_scan_pk,
    get_scan_for_owner,
    prune_scan_history,
    replace_scan_findings,
    scan_to_dict,
    scan_to_summary_dict,
    update_scan_fields,
)
from webapp.models import Finding, OOBIssuedToken, Scan, User
from webapp.tasks import run_scan as celery_run_scan

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "1440"))

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# 앱 전역 Redis 클라이언트 (lifespan에서 초기화/종료)
_redis_client: aioredis.Redis | None = None

SCAN_TYPES = [
    "all",
    "sqli",
    "osci",
    "oob_sqli",
    "oob_osci",
    "bruteforce",
    "lfi",
    "file_upload",
    "ssrf",
    "stored_xss",
    "reflected_xss",
    "ssti",
]


class AuthSettings(BaseModel):
    login_url: str = ""
    cookie: str = ""
    username: str = ""
    password: str = ""
    username_field: str = "username"
    password_field: str = "password"
    csrf_field: str = ""
    submit_field: str = ""
    login_json: bool = False
    login_body_format: Literal["auto", "form", "json"] = "auto"


class CrawlerOptions(BaseModel):
    crawl_mode: Literal["static", "dynamic"] = "static"
    spa_max_routes: int = Field(default=50, ge=1, le=500)
    unsafe_click: bool = False
    local_storage: str = "{}"
    exclude_urls: list[str] = Field(default_factory=list)
    fuzz_csrf: bool = False
    fuzz_auth: bool = False
    graphql_unsafe: bool = False
    exclude_auth_paths: list[str] = Field(default_factory=list)


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


class SSTIOptions(BaseModel):
    max_payloads: int = Field(
        default=0,
        ge=0,
        description="0=전체 페이로드, 0보다 크면 빠른 테스트용 상한",
    )


class ScanRequest(BaseModel):
    target_url: str = Field(..., min_length=1, max_length=2048, alias="url")
    scan_type: Literal[
        "all",
        "sqli",
        "osci",
        "oob_sqli",
        "oob_osci",
        "bruteforce",
        "lfi",
        "file_upload",
        "ssrf",
        "stored_xss",
        "reflected_xss",
        "ssti",
    ] = "all"
    level: int = Field(default=1, ge=0, le=3)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    crawler: CrawlerOptions = Field(default_factory=CrawlerOptions)
    engine: EngineOptions = Field(default_factory=EngineOptions)
    sqli: SQLiOptions = Field(default_factory=SQLiOptions)
    osci: OSCiOptions = Field(default_factory=OSCiOptions)
    bruteforce: BruteforceOptions = Field(default_factory=BruteforceOptions)
    ssrf: SSRFOptions = Field(default_factory=SSRFOptions)
    stored_xss: StoredXSSOptions = Field(default_factory=StoredXSSOptions)
    reflected_xss: ReflectedXSSOptions = Field(default_factory=ReflectedXSSOptions)
    ssti: SSTIOptions = Field(default_factory=SSTIOptions)

    model_config = {"populate_by_name": True}


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8, max_length=128)


def _seed_default_user(db: Session) -> None:
    if not DEFAULT_ADMIN_USERNAME:
        return
    exists = (
        db.query(User).filter(User.username == DEFAULT_ADMIN_USERNAME).first()
    )
    if exists is not None:
        return
    salt = secrets.token_hex(16)
    db.add(
        User(
            username=DEFAULT_ADMIN_USERNAME,
            salt=salt,
            password_hash=_hash_password(DEFAULT_ADMIN_PASSWORD, salt),
        )
    )
    db.commit()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _redis_client
    last_error: Exception | None = None
    for attempt in range(30):
        try:
            init_db()
            db = SessionLocal()
            try:
                _seed_default_user(db)
            finally:
                db.close()
            break
        except Exception as exc:
            last_error = exc
            time.sleep(2)
    else:
        raise RuntimeError(f"Database init failed after retries: {last_error}") from last_error

    try:
        _redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
        await _redis_client.ping()
        logger.info("Redis connected: %s", REDIS_URL)
    except Exception as exc:
        logger.warning("Redis unavailable at startup (%s) — OOB webhook will use DB fallback only", exc)
        _redis_client = None

    yield

    if _redis_client:
        await _redis_client.aclose()


app = FastAPI(
    title="Modular Web Scanner API",
    description="Web UI backend connected to the real CLI scan pipeline.",
    version="0.1.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

DEFAULT_ADMIN_USERNAME = os.getenv("DEFAULT_ADMIN_USERNAME", "admin").strip().lower()
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin1234")


def _hash_password(password: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()


def _create_access_token(user_id: int, username: str) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRES_MINUTES)
    payload = {
        "sub": str(user_id),
        "username": username,
        "exp": expires_at,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def _parse_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header is required.",
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Use Authorization: Bearer <token>.",
        )
    return token


def _get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    token = _parse_bearer_token(authorization)
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
        ) from exc

    raw_user_id = payload.get("sub")
    try:
        user_id = int(raw_user_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject.",
        ) from exc

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
        )
    return user


@app.post("/api/auth/register")
async def register_user(req: RegisterRequest, db: Session = Depends(get_db)) -> dict:
    normalized_username = req.username.strip().lower()
    if not normalized_username:
        raise HTTPException(status_code=400, detail="Username is required.")
    if db.query(User).filter(User.username == normalized_username).first():
        raise HTTPException(status_code=409, detail="Username already exists.")

    salt = secrets.token_hex(16)
    user = User(
        username=normalized_username,
        salt=salt,
        password_hash=_hash_password(req.password, salt),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"status": "created", "user_id": user.id, "username": user.username}


@app.post("/api/auth/login")
async def login_user(req: LoginRequest, db: Session = Depends(get_db)) -> dict:
    normalized_username = req.username.strip().lower()
    user = db.query(User).filter(User.username == normalized_username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    expected_hash = _hash_password(req.password, user.salt)
    if expected_hash != user.password_hash:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = _create_access_token(user.id, user.username)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user.id, "username": user.username},
        "expires_in_minutes": JWT_EXPIRES_MINUTES,
    }


@app.get("/api/auth/me")
async def get_me(current_user: User = Depends(_get_current_user)) -> dict:
    return {
        "id": current_user.id,
        "username": current_user.username,
        "created_at": current_user.created_at.timestamp(),
    }


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
            "crawl_mode": "static",
            "spa_max_routes": 50,
            "local_storage": "{}",
        },
    }


@app.post("/api/scan/start")
async def start_scan(
    req: ScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(_get_current_user),
) -> dict:
    scan_id = str(uuid4())
    request_payload = req.model_dump(by_alias=True)
    scan = Scan(
        scan_id=scan_id,
        owner_id=current_user.id,
        target_url=req.target_url,
        status="queued",
        progress=0,
        progress_percent=0.0,
        request_payload=request_payload,
        summary={
            "phase": "queued",
            "queued": 0,
            "completed": 0,
            "failures": 0,
            "findings": 0,
            "elapsed_time": 0.0,
        },
        logs=[],
    )
    db.add(scan)
    db.commit()
    prune_scan_history(db, current_user.id, keep=MAX_SCAN_HISTORY_PER_USER)
    # Celery 큐로 작업 위임 — FastAPI는 즉시 응답
    celery_run_scan.delay(scan_id, request_payload)
    return {
        "status": "accepted",
        "message": "Scan queued to Celery worker.",
        "scan_id": scan_id,
        "request": request_payload,
    }


@app.get("/api/scan/{scan_id}")
async def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(_get_current_user),
) -> dict:
    scan = get_scan_for_owner(db, scan_id, current_user.id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    findings_rows = findings_from_rows(scan.findings)
    return scan_to_dict(scan, findings_rows)


@app.get("/api/scans")
async def get_my_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(_get_current_user),
) -> dict:
    rows = (
        db.query(Scan)
        .filter(Scan.owner_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(MAX_SCAN_HISTORY_PER_USER)
        .all()
    )
    items = [scan_to_summary_dict(row) for row in rows]
    return {
        "items": items,
        "count": len(items),
        "max_stored": MAX_SCAN_HISTORY_PER_USER,
    }




# ──────────────────────────────────────────────────────────────────────────────
# OOB Webhook endpoint
# OOB 서버가 콜백을 감지하면 이 엔드포인트로 POST 요청을 보낸다.
# ──────────────────────────────────────────────────────────────────────────────

class OOBWebhookData(BaseModel):
    token: str
    source_ip: str = ""
    received_at: str = ""
    protocol: str = ""
    details: dict[str, Any] = {}


@app.post("/api/internal/oob-hit")
async def receive_oob_hit(data: OOBWebhookData) -> dict:
    """
    OOB 콜백 서버가 'w' 접두사 토큰을 수신하면 이 엔드포인트로 데이터를 전달한다.

    처리 순서:
    1. Redis에서 oob_map:{token} 조회 → scan_id, target, attack_info 획득
    2. Redis 미스 시 DB(OOBIssuedToken)로 fallback
    3. scan_id 로 Scan row 조회 → scan_pk 확보
    4. findings 테이블에 OOB Finding 추가
    5. Scan.summary.findings 카운트 갱신
    6. Redis 키 삭제 (중복 처리 방지)
    """
    token = data.token

    # 1. Redis 조회
    meta: dict | None = None
    if _redis_client is not None:
        try:
            raw = await _redis_client.get(f"oob_map:{token}")
            if raw:
                meta = json.loads(raw)
        except Exception as exc:
            logger.warning("Redis lookup failed for token %s: %s", token, exc)

    # 2. DB fallback (Redis TTL 만료 / Redis 미사용 환경)
    if meta is None:
        db_token = await _run_sync(get_oob_token_meta, token)
        if db_token is not None:
            meta = {
                "scan_id": db_token.scan_id,
                "module_name": db_token.module_name or "OOB",
                "target": {
                    "url": db_token.target_url or "",
                    "method": db_token.target_method or "GET",
                    "location": db_token.target_location or "",
                    "parameter": db_token.target_parameter or "",
                },
                "attack_info": {
                    "payload_value": db_token.payload_value or "",
                    "type": db_token.attack_type or "OOB",
                    "risk_level": db_token.risk_level or "High",
                },
            }

    if meta is None:
        logger.warning("OOB webhook: unknown token %s", token)
        raise HTTPException(status_code=404, detail=f"Unknown OOB token: {token}")

    scan_id: str = meta.get("scan_id", "")
    if not scan_id:
        logger.error("OOB webhook: meta for token %s has no scan_id", token)
        raise HTTPException(status_code=422, detail="Token metadata missing scan_id")

    # 3. Scan row 조회
    scan_row = await _run_sync(get_scan_by_public_id, scan_id)
    if scan_row is None:
        logger.error("OOB webhook: scan %s not found in DB (token=%s)", scan_id, token)
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    scan_pk: int = scan_row.id

    # 4. Finding 저장
    target = meta.get("target", {})
    attack_info = meta.get("attack_info", {})
    module_name = meta.get("module_name", "OOB")

    description = (
        f"[OOB Verified] {module_name} | "
        f"protocol={data.protocol} source_ip={data.source_ip} received_at={data.received_at} | "
        f"payload={attack_info.get('payload_value', '')}"
    )

    def _insert_finding():
        db = SessionLocal()
        try:
            finding = Finding(
                scan_id=scan_pk,
                vulnerability_type=attack_info.get("type", "OOB"),
                severity=attack_info.get("risk_level", "High"),
                location=target.get("location") or target.get("method"),
                parameter=target.get("parameter"),
                url=target.get("url"),
                payload=attack_info.get("payload_value"),
                description=description,
            )
            db.add(finding)

            # summary.findings 카운트 증가
            scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan:
                summary = dict(scan.summary or {})
                summary["findings"] = int(summary.get("findings", 0)) + 1
                scan.summary = summary
                scan.updated_at = datetime.now(timezone.utc)

            db.commit()
        finally:
            db.close()

    await _run_sync(_insert_finding)

    # 5. Redis 키 삭제 (중복 처리 방지)
    if _redis_client is not None:
        try:
            await _redis_client.delete(f"oob_map:{token}")
        except Exception as exc:
            logger.warning("Redis delete failed for token %s: %s", token, exc)

    logger.info(
        "OOB hit recorded — scan=%s token=%s proto=%s src=%s",
        scan_id, token, data.protocol, data.source_ip,
    )
    return {"status": "ok", "scan_id": scan_id, "token": token}


async def _run_sync(fn, *args, **kwargs):
    """동기 DB 함수를 asyncio 이벤트 루프에서 thread-safe하게 실행."""
    import asyncio
    return await asyncio.get_event_loop().run_in_executor(None, lambda: fn(*args, **kwargs))


@app.get("/health")
async def health_check() -> dict:
    return {"status": "ok"}


@app.get("/")
async def serve_index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
