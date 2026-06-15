from __future__ import annotations

import time
from datetime import datetime, timezone

from sqlalchemy.orm import Session, joinedload

from webapp.database import SessionLocal
from webapp.models import Finding, OOBIssuedToken, Scan, User

MAX_SCAN_HISTORY_PER_USER = 10
# psycopg/PostgreSQL bind parameter limit is 65535; keep IN batches well below that.
_OOB_TOKEN_BATCH_SIZE = 2000

_PHASE_RANK: dict[str, int] = {
    "queued": 0,
    "crawling": 1,
    "fuzzing": 2,
    "completed": 3,
}
_MONOTONIC_SUMMARY_COUNTERS = frozenset(
    {
        "queued",
        "completed",
        "failures",
        "findings",
        "findings_raw",
        "module_index",
        "module_count",
        "planned_requests",
        "total_requests",
        "observed_total",
    }
)


def merge_scan_summary(existing: dict | None, patch: dict | None) -> dict:
    """
    Merge summary JSON without regressing scan phase or cumulative counters.

    OOB webhooks and the Celery progress loop can update the same row concurrently;
    a stale read must not restore ``phase: crawling`` after fuzzing has started.
    """
    base = dict(existing or {})
    if not patch:
        return base
    merged = {**base, **patch}
    if "phase" in patch:
        old_phase = str(base.get("phase") or "")
        new_phase = str(patch.get("phase") or old_phase)
        old_rank = _PHASE_RANK.get(old_phase, -1)
        new_rank = _PHASE_RANK.get(new_phase, -1)
        merged["phase"] = new_phase if new_rank >= old_rank else old_phase
    for key in _MONOTONIC_SUMMARY_COUNTERS:
        if key in base or key in patch:
            merged[key] = max(int(base.get(key) or 0), int(patch.get(key) or 0))
    # ``module_index`` is monotonic above; ``current_module`` must advance in lockstep.
    if "current_module" in patch or "module_index" in patch:
        base_idx = int(base.get("module_index") or 0)
        patch_idx = int(patch.get("module_index") or 0)
        if patch_idx >= base_idx and patch.get("current_module"):
            merged["current_module"] = patch["current_module"]
        elif "current_module" in base:
            merged["current_module"] = base["current_module"]
    return merged


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


def _flat_finding_to_record(item: dict) -> dict:
    return {
        "target": {
            "url": item.get("url") or "",
            "method": item.get("method") or "",
            "location": item.get("location") or "",
            "parameter": item.get("parameter") or "",
        },
        "attack_info": {
            "type": item.get("type") or "Unknown",
            "severity": item.get("severity") or "high",
            "payload_value": item.get("payload") or "",
        },
        **({"module": item["module"]} if item.get("module") else {}),
    }


def _record_to_flat_finding(record: dict) -> dict:
    target = record.get("target") or {}
    attack = record.get("attack_info") or {}
    return {
        "severity": attack.get("severity") or "high",
        "location": target.get("location") or "",
        "parameter": target.get("parameter") or "",
        "url": target.get("url") or "",
        "type": attack.get("type") or "Unknown",
        "payload": attack.get("payload_value") or "",
    }


def dedupe_finding_dicts(items: list[dict]) -> list[dict]:
    """Collapse flat finding dicts to one entry per URL / parameter / attack class."""
    if not items:
        return []
    from reporter.dedupe import dedupe_vulnerabilities, vulnerability_sort_key

    records = [_flat_finding_to_record(item) for item in items]
    deduped = dedupe_vulnerabilities(records, mode="first_in_order")
    deduped_sorted = sorted(deduped, key=vulnerability_sort_key)
    return [_record_to_flat_finding(rec) for rec in deduped_sorted]


def finding_group_key(
    *,
    url: str | None,
    parameter: str | None,
    vulnerability_type: str | None,
    location: str | None = None,
    method: str | None = None,
    module: str | None = None,
) -> tuple[str, str, str, str, str]:
    from reporter.dedupe import vulnerability_group_key

    record = _flat_finding_to_record(
        {
            "url": url,
            "parameter": parameter,
            "type": vulnerability_type,
            "location": location,
            "method": method,
            **({"module": module} if module else {}),
        }
    )
    return vulnerability_group_key(record)


def findings_from_rows(rows: list[Finding]) -> list[dict]:
    raw = [
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
    return dedupe_finding_dicts(raw)


def count_deduped_findings(rows: list[Finding]) -> int:
    return len(findings_from_rows(rows))


def oob_finding_already_exists(
    db: Session,
    scan_pk: int,
    *,
    url: str | None,
    parameter: str | None,
    vulnerability_type: str | None,
    location: str | None = None,
) -> bool:
    target_key = finding_group_key(
        url=url,
        parameter=parameter,
        vulnerability_type=vulnerability_type,
        location=location,
    )
    existing_rows = db.query(Finding).filter(Finding.scan_id == scan_pk).all()
    for row in existing_rows:
        if finding_group_key(
            url=row.url,
            parameter=row.parameter,
            vulnerability_type=row.vulnerability_type,
            location=row.location,
        ) == target_key:
            return True
    return False


def get_scan_findings_rows(scan_pk: int) -> list[Finding]:
    db = SessionLocal()
    try:
        return db.query(Finding).filter(Finding.scan_id == scan_pk).all()
    finally:
        db.close()


def build_oob_report_json(scan: Scan, rows: list[Finding] | None = None) -> dict:
    """Build grouped deduped report JSON from persisted OOB webhook findings."""
    from fuzzer import EngineStats
    from reporter import ReportGenerator

    finding_rows = rows if rows is not None else list(scan.findings)
    flat = [
        {
            "severity": row.severity,
            "location": row.location or "",
            "parameter": row.parameter or "",
            "url": row.url or "",
            "type": row.vulnerability_type,
            "payload": row.payload or "",
        }
        for row in finding_rows
    ]
    records: list[dict] = []
    for item in dedupe_finding_dicts(flat):
        record = _flat_finding_to_record(item)
        record["evidence"] = {
            "status_code": 0,
            "response_time": 0.0,
            "error_log": "OOB Callback (verified)",
        }
        records.append(record)

    summary = scan.summary or {}
    stats = EngineStats(
        queued=int(scan.total_requests or summary.get("queued", 0) or 0),
        completed=int(summary.get("completed", 0) or 0),
        failures=int(summary.get("failures", 0) or 0),
        findings=len(finding_rows),
    )
    reporter = ReportGenerator(stats=stats, findings=[])
    return reporter.build_deduped_report_from_records(
        records,
        raw_findings_count=len(finding_rows),
    )


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
        if scan.status == "running":
            incoming_summary = fields.get("summary") if isinstance(fields.get("summary"), dict) else None
            old_summary = scan.summary or {}
            planned_grew = False
            if incoming_summary is not None:
                old_planned = int(
                    old_summary.get("planned_requests") or scan.total_requests or 0
                )
                new_planned = int(
                    incoming_summary.get("planned_requests") or old_planned
                )
                planned_grew = new_planned > old_planned
            if "progress_percent" in fields:
                incoming = float(fields["progress_percent"] or 0)
                current = float(scan.progress_percent or 0)
                if planned_grew:
                    fields["progress_percent"] = incoming
                else:
                    fields["progress_percent"] = (
                        incoming if incoming == 0 and current == 0 else max(current, incoming)
                    )
            if "progress" in fields:
                incoming_p = int(fields["progress"] or 0)
                current_p = int(scan.progress or 0)
                if planned_grew:
                    fields["progress"] = incoming_p
                else:
                    fields["progress"] = (
                        incoming_p if incoming_p == 0 and current_p == 0 else max(current_p, incoming_p)
                    )
        if "summary" in fields and isinstance(fields["summary"], dict):
            fields["summary"] = merge_scan_summary(scan.summary, fields["summary"])
        for key, value in fields.items():
            setattr(scan, key, value)
        scan.updated_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()


def _oob_token_from_item(item: dict) -> OOBIssuedToken:
    target = item.get("target", {})
    attack_info = item.get("attack_info", {})
    return OOBIssuedToken(
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
    )


def bulk_save_oob_tokens(issued_tokens: list[dict]) -> int:
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

    Returns the number of rows inserted.
    """
    if not issued_tokens:
        return 0

    inserted = 0
    db = SessionLocal()
    try:
        for offset in range(0, len(issued_tokens), _OOB_TOKEN_BATCH_SIZE):
            chunk = issued_tokens[offset : offset + _OOB_TOKEN_BATCH_SIZE]
            token_list = [t["token"] for t in chunk]
            existing = {
                row.token
                for row in db.query(OOBIssuedToken.token)
                .filter(OOBIssuedToken.token.in_(token_list))
                .all()
            }
            batch_inserted = 0
            for item in chunk:
                if item["token"] in existing:
                    continue
                db.add(_oob_token_from_item(item))
                batch_inserted += 1
            if batch_inserted:
                db.commit()
                inserted += batch_inserted
            else:
                db.rollback()
    finally:
        db.close()
    return inserted


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
        for item in dedupe_finding_dicts(serialized):
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
