"""
OOBModule - 테스트용 Out-of-Band 콜백 탐지 모듈

페이로드 형식: {OAST서버}/c/{uuid4().hex}
타겟 주입 후 OAST 콜백 수신 여부를 폴링합니다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from modules.base_module import BaseModule
from modules.oob.client import OASTClient

OOB_MODULE_REPORT_NAME = "OOB Callback Detection"

# 엔진 1차 요청용 (analyze에서 실제 랜덤 URL로 재주입)
_ENGINE_PLACEHOLDER_URL = "http://127.0.0.1/oob-placeholder"

_URL_PARAM_NAMES: tuple[str, ...] = (
    "url", "uri", "path", "dir", "dest", "target", "link", "page",
    "host", "domain", "site", "address", "file", "document", "folder",
    "include", "language", "template", "redirect", "callback", "next",
    "return", "image", "avatar", "src", "endpoint", "feed", "proxy",
    "webhook", "continue", "return_url", "upload_url",
)
_URL_VALUE_RE = re.compile(
    r"(?:^|\b)(?:https?://|//|file://|ftp://|"
    r"localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|\[::1\])",
    re.IGNORECASE,
)


@dataclass(slots=True, frozen=True)
class OOBPayload:
    value: str
    attack_type: str
    risk_level: str
    channel: str = "oob"


class OOBModule(BaseModule):
    """
    테스트용 OOB 모듈 (--type oob).

    1. analyze()에서 uuid4().hex 토큰 생성 → http://{OAST}/c/{token}
    2. requester()로 타겟에 주입
    3. OAST /api/check/{token} 폴링
    4. 콜백 수신 시 취약점 기록 (리포트에는 실제 콜백 URL 포함)
    """

    def __init__(
        self,
        oast_client: OASTClient,
        name: str = OOB_MODULE_REPORT_NAME,
    ) -> None:
        super().__init__(name)
        self._client = oast_client
        self._payloads: list[OOBPayload] = [
            OOBPayload(
                value=_ENGINE_PLACEHOLDER_URL,
                attack_type="OOB-Test",
                risk_level="high",
            )
        ]

    def get_payloads(self) -> list[OOBPayload]:
        return self._payloads

    async def analyze(
        self,
        response,
        payload: OOBPayload,
        elapsed_time: float,
        original_res=None,
        requester=None,
    ) -> bool | tuple[bool, list[str], OOBPayload]:
        token, callback_url = self._client.generate_token()

        if callable(requester):
            try:
                await requester(callback_url)
            except Exception:
                pass

        detail = await self._client.wait_for_callback(token)
        if detail is None:
            return False

        report_payload = OOBPayload(
            value=callback_url,
            attack_type="OOB-Test",
            risk_level="high",
        )
        evidences: list[str] = []
        if detail.source_ip:
            evidences.append(f"OAST callback from {detail.source_ip}")
        return True, evidences, report_payload

    def get_target_parameters(self, surface, parameters: list[str]) -> list[str]:
        surface_params: dict = getattr(surface, "parameters", {}) or {}
        selected: list[str] = []
        seen: set[str] = set()
        for param in parameters:
            key = str(param).lower()
            value = str(surface_params.get(param, ""))
            by_name = any(hint in key for hint in _URL_PARAM_NAMES)
            by_value = bool(_URL_VALUE_RE.search(value))
            if (by_name or by_value) and param not in seen:
                selected.append(param)
                seen.add(param)
        return selected
