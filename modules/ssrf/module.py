from __future__ import annotations

import re
from typing import Any

import aiohttp

from core.models import Payload
from modules.base_module import BaseModule
from modules.ssrf.analyzer import (
    analyze_ssrf,
    analyze_ssrf_content_proof,
    should_defer_ssrf_verify,
)
from modules.ssrf.payloads import SSRFPayload, get_ssrf_payloads
from modules.ssrf.verify import verify_ssrf_readback

# Default display name; keep in sync with ``__init__(name=...)`` default.
SSRF_MODULE_REPORT_NAME = "Server-Side Request Forgery"


class SSRFModule(BaseModule):
    _NAME_TARGETS = (
        "url",
        "uri",
        "path",
        "dir",
        "dest",
        "target",
        "link",
        "page",
        "host",
        "domain",
        "site",
        "address",
        "file",
        "document",
        "folder",
        "include",
        "language",
        "template",
        "redirect",
        "callback",
        "next",
        "return",
        "image",
        "avatar",
        "src",
        "endpoint",
        "feed",
        "proxy",
        "webhook",
        "continue",
        "return_url",
        "upload_url",
    )
    _VALUE_PATTERN = re.compile(
        r"(?:^|\b)(?:https?://|//|file://|ftp://|gopher://|dict://|"
        r"php://|sftp://|tftp://|ldap://|netdoc://|jar:|"
        r"localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|\[::1\])",
        re.IGNORECASE,
    )

    def __init__(
        self,
        name: str = SSRF_MODULE_REPORT_NAME,
        *,
        include_oob_templates: bool = False,
        bypass_level: int = 0,
    ):
        super().__init__(name)
        self._payloads: list[SSRFPayload] = get_ssrf_payloads(
            include_oob_templates=include_oob_templates,
            bypass_level=bypass_level,
        )
        self._last_verify_evidence: str = ""

    def get_payloads(self) -> list[Payload]:
        return self._payloads

    def analyze(
        self,
        response,
        payload: Payload,
        elapsed_time: float,
        original_res=None,
        requester=None,
        surface: Any = None,
    ) -> bool:
        if analyze_ssrf_content_proof(response, payload, elapsed_time, original_res):
            return True
        if surface is not None and should_defer_ssrf_verify(surface, response):
            return True
        return analyze_ssrf(response, payload, elapsed_time, original_res)

    async def verify(
        self,
        session: aiohttp.ClientSession,
        surface: Any,
        parameter: str,
        payload: Payload,
        response: Any,
        baseline_response: Any,
    ) -> bool:
        verified, evidence = await verify_ssrf_readback(
            session,
            surface=surface,
            parameter=parameter,
            payload=payload,
            response=response,
            baseline_response=baseline_response,
        )
        self._last_verify_evidence = evidence
        return verified

    def get_target_parameters(self, surface, parameters: list[str]) -> list[str]:
        surface_params: dict = getattr(surface, "parameters", {}) or {}
        selected: list[str] = []
        seen: set[str] = set()
        for param in parameters:
            key = str(param).lower()
            value = str(surface_params.get(param, ""))
            by_name = any(target in key for target in self._NAME_TARGETS)
            by_value = bool(self._VALUE_PATTERN.search(value))
            if by_name or by_value:
                if param not in seen:
                    selected.append(param)
                    seen.add(param)
        return selected
