from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from webapp.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    salt: Mapped[str] = mapped_column(String(64), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="owner")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    owner_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    progress: Mapped[int] = mapped_column(Integer, default=0)
    progress_percent: Mapped[float] = mapped_column(default=0.0)
    request_payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    logs: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    report_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_requests: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    owner: Mapped["User"] = relationship("User", back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vulnerability_type: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    location: Mapped[str | None] = mapped_column(String(128), nullable=True)
    parameter: Mapped[str | None] = mapped_column(String(256), nullable=True)
    url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")


class OOBIssuedToken(Base):
    """
    Celery 워커가 OOB 페이로드를 주입할 때 발급한 토큰을 scan_id에 매핑해 저장.
    Redis TTL 만료 후에도 어떤 스캔에서 발급된 토큰인지 추적 가능하도록 DB에도 기록.
    """
    __tablename__ = "oob_issued_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    token: Mapped[str] = mapped_column(String(16), unique=True, index=True, nullable=False)
    scan_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    module_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    target_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    target_parameter: Mapped[str | None] = mapped_column(String(256), nullable=True)
    target_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    target_location: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    attack_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
