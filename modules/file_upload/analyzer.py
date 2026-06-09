from __future__ import annotations

import json
import re

from modules.file_upload.payloads import FilePayload
from modules.stored_xss.analyzer import (
    _redirect_implies_auth_failure,
    looks_like_successful_store_api_response,
)

SUCCESS_SIGNATURES = [
    r"succes+fully uploaded",
    r"upload complete",
    r"file uploaded successfully",
    r"the file.+has been uploaded",
    r"saved to",
    r"uploads?/",
]

# Phrase-level only — bare "error"/"failed" false-positive on board XSS titles (onerror=).
ERROR_PHRASES = (
    "upload failed",
    "failed to upload",
    "invalid file",
    "not uploaded",
    "not allowed",
    "forbidden file type",
    "file type not allowed",
)


def _response_indicates_upload_failure(res_lower: str) -> bool:
    return any(phrase in res_lower for phrase in ERROR_PHRASES)


_JSON_UPLOAD_PATH_KEYS = frozenset(
    {
        "url",
        "path",
        "file",
        "filename",
        "fileurl",
        "file_url",
        "filepath",
        "file_path",
        "attachment",
        "attachment_url",
        "location",
        "src",
        "href",
        "download",
        "link",
        "redirect",
    }
)

_LISTING_PAGE_HINTS = (
    "board-table",
    "/view?id=",
    "/view/",
    "/detail?",
    "/detail/",
    "/posts/",
    "/articles/",
)


def _json_indicates_upload_success(body: str, filename: str) -> tuple[bool, list[str]]:
    """SPA/REST mutation 응답(JSON)에서 업로드 성공 신호 추출."""
    text = (body or "").strip()
    if not text.startswith("{"):
        return False, []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return False, []
    if not isinstance(data, dict):
        return False, []

    evidences: list[str] = []
    if data.get("error"):
        return False, evidences

    filename_lower = filename.lower()
    basename = filename_lower.rsplit("/", 1)[-1]

    for key, value in data.items():
        key_lower = str(key).lower()
        if key_lower in _JSON_UPLOAD_PATH_KEYS and isinstance(value, str) and value.strip():
            value_lower = value.lower()
            if "upload" in value_lower or basename in value_lower:
                evidences.append(f"[JsonUploadPath] {key}={value[:120]}")

    redirect = data.get("redirect")
    if redirect and not _redirect_implies_auth_failure(str(redirect)):
        evidences.append(f"[JsonRedirect] {redirect}")

    if data.get("success") is True or data.get("ok") is True:
        evidences.append("[JsonSuccessFlag] mutation accepted")

    return (len(evidences) > 0), evidences


def detect_file_upload(response, payload) -> tuple[bool, list[str]]:
    """
    Stage-1: probable upload success (WAF bypass / storage), before active verification.
    """
    if not isinstance(payload, FilePayload):
        return False, []

    evidences: list[str] = []
    res_text = response.text or ""
    res_lower = res_text.lower()

    if _response_indicates_upload_failure(res_lower):
        return False, evidences

    response_url = str(getattr(response, "url", "") or "").lower()

    if looks_like_successful_store_api_response(response, res_text):
        evidences.append("[StoreApiSuccess] mutation accepted (JSON)")

    json_hit, json_evidences = _json_indicates_upload_success(res_text, payload.filename)
    if json_hit:
        evidences.extend(json_evidences)

    if any(hint in res_lower for hint in _LISTING_PAGE_HINTS):
        evidences.append(f"[ListingRedirect] post-submit listing ({response_url})")

    for pattern in SUCCESS_SIGNATURES:
        if re.search(pattern, res_lower, re.IGNORECASE):
            evidences.append(f"[SuccessSignature] matched: {pattern}")
            break

    if payload.filename.lower() in res_lower:
        evidences.append(f"[FilenameReflection] {payload.filename}")

    return (len(evidences) > 0), evidences
