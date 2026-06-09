from __future__ import annotations

import time
from datetime import datetime, timezone

from sqlalchemy.orm import Session, joinedload

from webapp.database import SessionLocal
from webapp.models import Finding, OOBIssuedToken, Scan, User

MAX_SCAN_HISTORY_PER_USER = 10


def _ts(dt: datetime | None) -> float:
    if dt is None:
        return time.time()
    if dt.tzinfo is None:
        return dt.timestamp()
    return dt.timestamp()


def scan_to_dict(scan: Scan, findings_rows: list[dict] | None = None) -> dict:
    return {
        "scan_id": scan.scan_id,
        "owner_id": scan.owner_id,
        "status": scan.status,
        "progress": scan.progress,
        "progress_percent": scan.progress_percent,
        "created_at": _ts(scan.created_at),
        "updated_at": _ts(scan.updated_at),
        "request": scan.request_payload,
        "target": scan.target_url,
        "findings": findings_rows if findings_rows is not None else [],
        "summary": scan.summary or {},
        "logs": scan.logs or [],
        "report_json": scan.report_json,
        "result": scan.result,
        "error": scan.error,
        "total_requests": scan.total_requests,
    }


def scan_to_summary_dict(scan: Scan) -> dict:
    summary = scan.summary or {}
    payload = scan.request_payload or {}
    scan_type = payload.get("scan_type") or payload.get("type") or "-"
    return {
        "scan_id": scan.scan_id,
        "target": scan.target_url,
        "status": scan.status,
        "progress_percent": scan.progress_percent,
        "created_at": _ts(scan.created_at),
        "scan_type": scan_type,
        "findings_count": int(summary.get("findings", 0) or 0),
    }


def prune_scan_history(db: Session, owner_id: int, keep: int = MAX_SCAN_HISTORY_PER_USER) -> int:
    """Keep only the newest `keep` scans per user; return number deleted."""
    ids = [
        row[0]
        for row in db.query(Scan.id)
        .filter(Scan.owner_id == owner_id)
        .order_by(Scan.created_at.desc())
        .all()
    ]
    if len(ids) <= keep:
        return 0
    drop_ids = ids[keep:]
    deleted = (
        db.query(Scan)
        .filter(Scan.id.in_(drop_ids))
        .delete(synchronize_session=False)
    )
    db.commit()
    return deleted


def findings_from_rows(rows: list[Finding]) -> list[dict]:
    return [
        {
            "severity": row.severity,
            "location": row.location or "",
            "parameter": row.parameter or "",
            "url": row.url or "",
            "type": row.vulnerability_type,
            "payload": row.payload or "",
        }
        for row in rows
    ]


def get_scan_for_owner(db: Session, scan_id: str, owner_id: int) -> Scan | None:
    return (
        db.query(Scan)
        .options(joinedload(Scan.findings))
        .filter(Scan.scan_id == scan_id, Scan.owner_id == owner_id)
        .first()
    )


def get_scan_by_public_id(scan_id: str) -> Scan | None:
    db = SessionLocal()
    try:
        return db.query(Scan).filter(Scan.scan_id == scan_id).first()
    finally:
        db.close()


def get_scan_pk(scan_id: str) -> int | None:
    scan = get_scan_by_public_id(scan_id)
    return scan.id if scan else None


def append_scan_log(scan_id: str, message: str) -> None:
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if scan is None:
            return
        logs = list(scan.logs or [])
        logs.append(f"[{time.strftime('%H:%M:%S')}] {message}")
        scan.logs = logs
        scan.updated_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()


def update_scan_fields(scan_id: str, **fields) -> None:
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if scan is None:
            return
        for key, value in fields.items():
            setattr(scan, key, value)
        scan.updated_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()


def bulk_save_oob_tokens(issued_tokens: list[dict]) -> None:
    """
    Celery 스캔 완료 후 발급된 OOB 토큰 목록을 DB에 일괄 저장.
    이미 존재하는 토큰은 ON CONFLICT 처리 대신 개별 무시 처리.

    각 항목 형식 (base_oob_module.generated_tokens 원소):
    {
        "token": str,
        "scan_id": str,
        "module_name": str,
        "target": {"url", "method", "location", "parameter"},
        "attack_info": {"payload_value", "type", "risk_level"}
    }
    """
    if not issued_tokens:
        return
    db = SessionLocal()
    try:
        existing = {
            row.token
            for row in db.query(OOBIssuedToken.token)
            .filter(OOBIssuedToken.token.in_([t["token"] for t in issued_tokens]))
            .all()
        }
        to_insert = [t for t in issued_tokens if t["token"] not in existing]
        for item in to_insert:
            target = item.get("target", {})
            attack_info = item.get("attack_info", {})
            db.add(OOBIssuedToken(
                token=item["token"],
                scan_id=item.get("scan_id", ""),
                module_name=item.get("module_name"),
                target_url=target.get("url"),
                target_parameter=target.get("parameter"),
                target_method=target.get("method"),
                target_location=target.get("location"),
                payload_value=attack_info.get("payload_value"),
                attack_type=attack_info.get("type"),
                risk_level=attack_info.get("risk_level"),
            ))
        if to_insert:
            db.commit()
    finally:
        db.close()


def get_oob_token_meta(token: str) -> OOBIssuedToken | None:
    """webhook 수신 시 token → DB 메타 조회 (Redis 만료 fallback)."""
    db = SessionLocal()
    try:
        return db.query(OOBIssuedToken).filter(OOBIssuedToken.token == token).first()
    finally:
        db.close()


def replace_scan_findings(scan_pk: int, serialized: list[dict]) -> None:
    db = SessionLocal()
    try:
        db.query(Finding).filter(Finding.scan_id == scan_pk).delete()
        for item in serialized:
            db.add(
                Finding(
                    scan_id=scan_pk,
                    vulnerability_type=str(item.get("type", "Unknown")),
                    severity=str(item.get("severity", "unknown")),
                    location=item.get("location"),
                    parameter=item.get("parameter"),
                    url=item.get("url"),
                    payload=item.get("payload"),
                )
            )
        db.commit()
    finally:
        db.close()
