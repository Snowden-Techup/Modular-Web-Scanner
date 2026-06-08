
from __future__ import annotations

import hashlib
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi import Depends, Header, status
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import jwt

from modules.oob.client import DEFAULT_OAST_SERVER_URL
from webapp.celery_app import celery_app  # noqa: F401 — Celery 앱 등록
from webapp.database import get_db, init_db
from webapp.database import SessionLocal
from webapp.db_service import (
    MAX_SCAN_HISTORY_PER_USER,
    findings_from_rows,
    get_scan_for_owner,
    prune_scan_history,
    scan_to_dict,
    scan_to_summary_dict,
)
from webapp.models import Scan, User
from webapp.tasks import run_scan as celery_run_scan

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "1440"))

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
    "ssti",
    "oob",
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
    crawl_mode: Literal["static", "dynamic", "hybrid"] = "static"
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
        "ssti",
        "oob",
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
    oob: OOBOptions = Field(default_factory=OOBOptions)

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
    yield


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
            "oob_server": DEFAULT_OAST_SERVER_URL,
            "oob_retries": 3,
            "oob_poll_delay": 5.0,
            "oob_poll_timeout": 10.0,
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
    request_payload["scan_id"] = scan_id
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




@app.get("/health")
async def health_check() -> dict:
    return {"status": "ok"}


@app.get("/")
async def serve_index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")