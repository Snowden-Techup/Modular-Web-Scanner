from __future__ import annotations

import re
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit

from modules.file_upload.markers import (
    CATEGORY_RCE,
    CATEGORY_STATIC_MALICIOUS_FILE,
    CATEGORY_TEMPLATE_RCE,
    CATEGORY_UNRESTRICTED_UPLOAD,
    DEFAULT_SHELL_TAGS_BY_MODE,
    NODE_TEMPLATE_TAGS,
    PHP_SHELL_TAGS,
    RCE_PHP_MARKER,
    VERIFY_RCE,
    VERIFY_STATIC,
    VERIFY_TEMPLATE,
)

if TYPE_CHECKING:
    from modules.file_upload.payloads import FilePayload

# Backward-compatible export used by module/tests.
EXECUTION_MARKER = RCE_PHP_MARKER


@dataclass(frozen=True, slots=True)
class VerificationResult:
    verified: bool
    category: str
    severity: str
    evidences: list[str]


class UploadPathExtractor(HTMLParser):
    _CANDIDATE_ATTRS = ("href", "src", "action", "value", "data-url", "data-file")

    def __init__(self, filename: str) -> None:
        super().__init__()
        self.filename = filename.lower()
        self.paths: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for key, value in attrs:
            if value is None:
                continue
            if key.lower() not in self._CANDIDATE_ATTRS:
                continue
            self._add_if_match(value)

    def handle_data(self, data: str) -> None:
        self._add_if_match(data)

    def _add_if_match(self, value: str) -> None:
        raw = unescape(value).strip().strip("'\"")
        if not raw:
            return
        if self.filename not in raw.lower():
            return
        self.paths.add(raw)


def extract_dynamic_verify_urls(base_url: str, response_text: str, filename: str) -> list[str]:
    """Backward-compatible wrapper around path_discovery strategy 1."""
    from modules.file_upload.path_discovery import extract_paths_from_text, merge_verify_urls

    class _PayloadShim:
        verify_paths: tuple[str, ...] = ()
        verify_mode: str = ""

    paths = extract_paths_from_text(response_text, filename)
    return merge_verify_urls(
        base_url=base_url,
        filename=filename,
        discovered_paths=paths,
        payload=_PayloadShim(),
        include_fallback=False,
    )


def is_direct_upload_file_url(url: str, filename: str) -> bool:
    """URL path에 업로드 파일명(베이스네임)이 포함되면 직접 파일 서빙으로 간주."""
    basename = (filename or "").rsplit("/", 1)[-1].strip().lower()
    if not basename:
        return False
    return basename in (urlsplit(url).path or "").lower()


def _body_contains_any(body: str, needles: tuple[str, ...]) -> bool:
    lower = body.lower()
    return any(needle.lower() in lower for needle in needles if needle)


def _shell_tags_for_payload(payload: FilePayload) -> tuple[str, ...]:
    if payload.shell_tags:
        return payload.shell_tags
    return DEFAULT_SHELL_TAGS_BY_MODE.get(payload.verify_mode, PHP_SHELL_TAGS)


def verify_upload_response(
    body: str,
    payload: FilePayload,
    *,
    direct_file: bool = False,
) -> VerificationResult:
    """
    Active verification: distinguish executed code (RCE) vs static file serve.
    ``direct_file=True`` — 업로드된 파일 URL 자체를 GET한 경우 (PHP가 Node에서 미실행 등).
    """
    evidences: list[str] = []
    mode = (payload.verify_mode or VERIFY_RCE).lower()

    if mode == VERIFY_STATIC:
        probe = (payload.content_probe or payload.marker or "").strip()
        if not probe:
            return VerificationResult(False, "static", "high", evidences)
        if probe not in body:
            return VerificationResult(False, CATEGORY_STATIC_MALICIOUS_FILE, "high", evidences)
        evidences.append(f"[StaticServe] probe reflected: {probe[:80]}")
        return VerificationResult(True, CATEGORY_STATIC_MALICIOUS_FILE, "high", evidences)

    if mode == VERIFY_TEMPLATE:
        marker = payload.marker
        if marker not in body:
            return VerificationResult(False, CATEGORY_TEMPLATE_RCE, "critical", evidences)
        if _body_contains_any(body, _shell_tags_for_payload(payload) or NODE_TEMPLATE_TAGS):
            return VerificationResult(False, CATEGORY_TEMPLATE_RCE, "critical", evidences)
        evidences.append(f"[TemplateRCE] marker rendered without template tags: {marker}")
        return VerificationResult(True, CATEGORY_TEMPLATE_RCE, "critical", evidences)

    # VERIFY_RCE — marker must appear and interpreter tags must be stripped.
    marker = payload.marker
    if marker not in body:
        return VerificationResult(False, CATEGORY_RCE, "critical", evidences)
    if _body_contains_any(body, _shell_tags_for_payload(payload)):
        if direct_file:
            evidences.append(
                f"[UnrestrictedUpload] marker in served file (interpreter not executed): {marker}"
            )
            return VerificationResult(True, CATEGORY_UNRESTRICTED_UPLOAD, "high", evidences)
        return VerificationResult(False, CATEGORY_RCE, "critical", evidences)
    evidences.append(f"[RCE] marker executed (shell tags absent): {marker}")
    return VerificationResult(True, CATEGORY_RCE, "critical", evidences)


def build_verify_url_list(
    *,
    base_url: str,
    upload_response_text: str,
    payload: FilePayload,
    surface_url: str = "",
    include_fallback: bool = True,
) -> list[str]:
    """Sync URL list: upload response parsing + optional directory fallback."""
    from modules.file_upload.path_discovery import extract_paths_from_text, merge_verify_urls

    paths = extract_paths_from_text(upload_response_text, payload.filename)
    return merge_verify_urls(
        base_url=base_url,
        filename=payload.filename,
        discovered_paths=paths,
        payload=payload,
        surface_url=surface_url,
        include_fallback=include_fallback,
    )
