"""
OAST (Out-of-band Application Security Testing) 클라이언트

AWS 등 외부에 띄워둔 독립형 OAST 서버와 통신합니다.
- generate_token() : 고유 토큰 + 콜백 URL 생성
- poll()           : 단일 콜백 수신 확인
- wait_for_callback() : 재시도 폴링 (비동기, 논블로킹)

다른 모듈에서 임포트해 사용하는 방법:
    from modules.oob.client import OASTClient

    client = OASTClient("https://oob.example.com")

    # analyze() 안에서 사용 예시
    token, callback_url = client.generate_token()
    await requester(callback_url)          # 타겟에 OOB URL 주입
    detail = await client.wait_for_callback(token)
    return detail is not None              # 콜백 수신 여부
"""
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import aiohttp

DEFAULT_OAST_SERVER_URL = "http://3.34.47.231"

# 이전 EC2 OAST — UI/저장값에 남아 있으면 현재 서버로 치환
_LEGACY_OAST_SERVER_URLS: tuple[str, ...] = (
    "http://15.164.99.243",
    "https://15.164.99.243",
    "15.164.99.243",
)


def normalize_oast_server_url(url: str) -> str:
    """빈 값·레거시 IP는 DEFAULT_OAST_SERVER_URL로 통일."""
    raw = (url or "").strip()
    if not raw:
        return DEFAULT_OAST_SERVER_URL
    lowered = raw.lower().rstrip("/")
    for legacy in _LEGACY_OAST_SERVER_URLS:
        leg = legacy.lower().rstrip("/")
        if lowered == leg or lowered.startswith(f"{leg}/"):
            return DEFAULT_OAST_SERVER_URL
    if lowered.startswith(("http://", "https://")):
        return raw.rstrip("/")
    return f"http://{raw.lstrip('/')}".rstrip("/")


@dataclass
class OASTCallbackDetail:
    """OAST 서버가 콜백을 수신했을 때 반환하는 메타데이터."""

    token: str
    source_ip: str = ""
    user_agent: str = ""
    received_at: float = field(default_factory=time.time)
    raw: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"OASTCallbackDetail(token={self.token!r}, "
            f"source_ip={self.source_ip!r}, "
            f"received_at={self.received_at:.1f})"
        )


class OASTClient:
    """
    독립형 OAST 서버 클라이언트.

    OAST 서버 API 규약 (서버 측 구현 참고):
        GET /c/{token}         → 타겟이 접속하는 콜백 수신 엔드포인트
        GET /api/check/{token} → 스캐너가 수신 여부를 확인하는 API
            응답 형식: {"vulnerable": true/false, "details": {"ip": "...", "user_agent": "..."}}

    매개변수:
        server_url    : OAST 서버 기본 URL (예: "https://oob.example.com")
        poll_retries  : 최대 폴링 횟수 (기본 3회)
        poll_delay    : 폴링 간격(초) — 선형 증가 (기본 5초)
                        스케줄: delay×1, delay×2, ..., delay×retries
        poll_timeout  : OAST API 단일 HTTP 요청 타임아웃(초) (기본 10초)
    """

    def __init__(
        self,
        server_url: str,
        *,
        poll_retries: int = 3,
        poll_delay: float = 5.0,
        poll_timeout: float = 10.0,
    ) -> None:
        normalized = normalize_oast_server_url(server_url)
        if not normalized:
            raise ValueError("server_url must not be empty")
        self.server_url = normalized
        self.poll_retries = max(1, int(poll_retries))
        self.poll_delay = max(1.0, float(poll_delay))
        self.poll_timeout = max(1.0, float(poll_timeout))

    # ─── 토큰/URL 생성 ───────────────────────────────────────────────────────

    def generate_token(self) -> tuple[str, str]:
        """
        UUID 기반 고유 토큰을 발급하고 (token, callback_url) 튜플을 반환합니다.

        callback_url 형식: {server_url}/c/{token}
        예: "https://oob.example.com/c/a3f9c2d1e4b7..."

        반환된 callback_url을 페이로드로 타겟에 주입하고,
        token으로 OAST 서버에 수신 여부를 문의합니다.
        """
        token = uuid.uuid4().hex
        callback_url = f"{self.server_url}/c/{token}"
        return token, callback_url

    # ─── 폴링 ────────────────────────────────────────────────────────────────

    async def poll(self, token: str) -> OASTCallbackDetail | None:
        """
        OAST API를 1회 조회합니다.

        콜백이 기록되어 있으면 OASTCallbackDetail을 반환하고,
        그렇지 않으면 None을 반환합니다.
        네트워크 오류 발생 시에도 None을 반환합니다(예외 미전파).
        """
        check_url = f"{self.server_url}/api/check/{token}"
        timeout = aiohttp.ClientTimeout(total=self.poll_timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(check_url) as resp:
                    if resp.status != 200:
                        return None
                    data: dict[str, Any] = await resp.json(content_type=None)
                    if not data.get("vulnerable"):
                        return None
                    return self._parse_detail(token, data)
        except Exception:
            return None

    async def wait_for_callback(self, token: str) -> OASTCallbackDetail | None:
        """
        콜백 수신 여부를 선형 증가 간격으로 반복 폴링합니다.

        폴링 스케줄 (poll_retries=3, poll_delay=5):
            5초 대기 → 폴링 #1
            10초 대기 → 폴링 #2
            15초 대기 → 폴링 #3

        콜백이 확인되면 즉시 OASTCallbackDetail을 반환합니다.
        최대 재시도 후 수신이 없으면 None을 반환합니다.
        """
        for attempt in range(self.poll_retries):
            wait_secs = self.poll_delay * (attempt + 1)
            await asyncio.sleep(wait_secs)
            detail = await self.poll(token)
            if detail is not None:
                return detail
        return None

    # ─── 내부 헬퍼 ───────────────────────────────────────────────────────────

    @staticmethod
    def _parse_detail(token: str, data: dict[str, Any]) -> OASTCallbackDetail:
        raw_details = data.get("details") or {}
        if isinstance(raw_details, str):
            import ast
            try:
                raw_details = ast.literal_eval(raw_details)
            except Exception:
                raw_details = {}
        return OASTCallbackDetail(
            token=token,
            source_ip=str(raw_details.get("ip", "")),
            user_agent=str(raw_details.get("user_agent", "")),
            raw=data,
        )

    def __repr__(self) -> str:
        return (
            f"OASTClient(server={self.server_url!r}, "
            f"retries={self.poll_retries}, delay={self.poll_delay}s)"
        )
