from __future__ import annotations

import re
import uuid
from typing import Any

_CLOUD_TARGET_HINTS = (
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",
    "192.0.0.192",
    "169.254.170.2",
)
_CLOUD_SUCCESS_HINTS = (
    "ami-id",
    "instance-id",
    "local-ipv4",
    "accesskeyid",
    "secretaccesskey",
    "computemetadata",
    "x-aws-ec2-metadata-token",
    "metadata-flavor",
)
_CLOUD_ERROR_HINTS = (
    "metadata-flavor",
    "aws-ec2-metadata",
    "required header",
    "x-aws-ec2-metadata-token",
)
_INTERNAL_NETWORK_ERROR_HINTS = (
    "connection refused",
    "econnrefused",
    "no route to host",
    "name or service not known",
    "network is unreachable",
    "connection timed out",
    "etimedout",
    "ehostunreach",
    "enotfound",
    "ssh-2.0",
    "redis_version",
)
_LOCALHOST_TARGET_HINTS = (
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
    "::1",
)
_LOGIN_PAGE_HINTS = (
    "login",
    "sign in",
    "username",
    "password",
    "remember me",
)
_BLIND_PROBE_HINTS = (
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
    "::1",
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.2",
    "172.30.",
    "172.31.",
    "192.168.",
    "169.254.",
    "file://",
)


def _extract_response_text(response) -> str:
    if isinstance(response, str):
        return response
    text_attr = getattr(response, "text", "")
    if callable(text_attr):
        try:
            return str(text_attr())
        except Exception:
            return str(response)
    return str(text_attr or "")


def _extract_status_code(response) -> int:
    status_code = getattr(response, "status_code", None)
    if status_code is not None:
        return int(status_code)
    status = getattr(response, "status", None)
    if status is not None:
        return int(status)
    return 0


def _status_class(status_code: int) -> int:
    if status_code <= 0:
        return 0
    return status_code // 100


def _is_blind_probe_payload(payload_value_lower: str) -> bool:
    return any(hint in payload_value_lower for hint in _BLIND_PROBE_HINTS)


def _probe_url_echoed_in_body(res_text_lower: str, payload_value_lower: str) -> bool:
    """True if the response body contains the probe URL (typical reflected CSP/XSS sinks)."""
    if len(payload_value_lower) < 8:
        return False
    if payload_value_lower in res_text_lower:
        return True
    if payload_value_lower.startswith("http://"):
        rest = payload_value_lower.removeprefix("http://")
        if len(rest) >= 6 and rest in res_text_lower:
            return True
    if payload_value_lower.startswith("https://"):
        rest = payload_value_lower.removeprefix("https://")
        if len(rest) >= 6 and rest in res_text_lower:
            return True
    return False


def _match_signature_proof(
    res_text: str,
    res_text_lower: str,
    *,
    expected_signature: str | None,
    payload_value_lower: str,
    original_text_lower: str,
) -> bool:
    if not expected_signature:
        return False
    try:
        m_current = re.search(expected_signature, res_text, re.IGNORECASE | re.DOTALL)
        matched_original = bool(
            original_text_lower
            and re.search(expected_signature, original_text_lower, re.IGNORECASE | re.DOTALL)
        )
        if m_current and not matched_original:
            hit = m_current.group(0).lower()
            if hit and hit not in payload_value_lower:
                return True
    except re.error:
        expected_lower = expected_signature.lower()
        if (
            expected_lower in res_text_lower
            and expected_lower not in original_text_lower
            and expected_lower not in payload_value_lower
        ):
            return True
    return False


def _match_cloud_proof(
    res_text_lower: str,
    *,
    payload_value_lower: str,
    original_text_lower: str,
    status_code: int,
) -> bool:
    is_cloud_payload = any(hint in payload_value_lower for hint in _CLOUD_TARGET_HINTS)
    if not is_cloud_payload:
        return False
    new_cloud_hints = [
        hint
        for hint in _CLOUD_SUCCESS_HINTS
        if hint in res_text_lower
        and hint not in original_text_lower
        and hint not in payload_value_lower
    ]
    if status_code == 200 and new_cloud_hints:
        return True
    if status_code in (400, 401, 403) and any(
        hint in res_text_lower for hint in _CLOUD_ERROR_HINTS
    ):
        return True
    return False


def _match_internal_network_proof(res_text_lower: str) -> bool:
    return any(hint in res_text_lower for hint in _INTERNAL_NETWORK_ERROR_HINTS)


def _match_time_proof(payload_value_lower: str, elapsed_time: float) -> bool:
    return (
        "10.255.255.255" in payload_value_lower or ":22" in payload_value_lower
    ) and elapsed_time > 10.0


def analyze_ssrf_content_proof(
    response,
    payload,
    elapsed_time: float = 0.0,
    original_res=None,
) -> bool:
    """
    Direct SSRF evidence in the response body (signatures, cloud hints, fetch errors).
    Excludes boolean-blind length/status deltas that cause MPA redirect false positives.
    """
    res_text = _extract_response_text(response)
    res_text_lower = res_text.lower()
    original_text = _extract_response_text(original_res) if original_res is not None else ""
    original_text_lower = original_text.lower()
    status_code = _extract_status_code(response)
    payload_value = str(getattr(payload, "value", ""))
    payload_value_lower = payload_value.lower()
    expected_signature = getattr(payload, "expected_signature", None)

    if _match_signature_proof(
        res_text,
        res_text_lower,
        expected_signature=expected_signature,
        payload_value_lower=payload_value_lower,
        original_text_lower=original_text_lower,
    ):
        return True
    if _match_cloud_proof(
        res_text_lower,
        payload_value_lower=payload_value_lower,
        original_text_lower=original_text_lower,
        status_code=status_code,
    ):
        return True
    if _match_internal_network_proof(res_text_lower):
        return True
    if _match_time_proof(payload_value_lower, elapsed_time):
        return True
    return False


def analyze_ssrf_readback_proof(res_text: str, payload) -> bool:
    """SSRF proof in a read-back GET body (stored content, detail API, etc.)."""

    class _ReadbackResponse:
        def __init__(self, text: str) -> None:
            self.text = text
            self.status_code = 200

    return analyze_ssrf_content_proof(_ReadbackResponse(res_text), payload)


def build_ssrf_verify_probe() -> tuple[str, int, str]:
    """
    Unique localhost probe for 2nd-stage verification.
    Port + path token tie read-back evidence to *this* injection only.
    """
    verify_id = uuid.uuid4().hex[:8]
    probe_port = 40000 + (int(verify_id, 16) % 20000)
    probe_url = f"http://127.0.0.1:{probe_port}/vfy-{verify_id}/"
    return verify_id, probe_port, probe_url


def readback_shows_new_verify_probe(
    pre_body: str,
    post_body: str,
    *,
    verify_id: str,
    probe_port: int,
) -> bool:
    """
    True when post_body contains SSRF side-effect markers from this verify probe
    that were absent in pre_body (prevents cross-surface / prior-scan contamination).
    """
    pre_lower = (pre_body or "").lower()
    post_lower = (post_body or "").lower()
    if not post_lower or post_lower == pre_lower:
        return False

    token = verify_id.lower()
    if token in post_lower and token not in pre_lower:
        return True

    port_needle = f":{probe_port}"
    if port_needle in post_lower and port_needle not in pre_lower:
        if any(hint in post_lower for hint in _INTERNAL_NETWORK_ERROR_HINTS):
            return True
    return False


def should_defer_ssrf_verify(surface: Any, response: Any) -> bool:
    """
    Mutating write accepted but the inline response lacks SSRF proof (SPA JSON redirect, etc.).
  Reuses stored_xss store-success heuristics; no app-specific URLs.
    """
    from modules.stored_xss.analyzer import (
        injection_response_implies_failed_auth,
        is_store_mutation_surface,
        looks_like_successful_store_api_response,
        looks_like_successful_store_redirect,
    )

    if surface is None or not is_store_mutation_surface(surface):
        return False
    if injection_response_implies_failed_auth(response):
        return False
    body = _extract_response_text(response)
    if looks_like_successful_store_api_response(response, body):
        return True
    return looks_like_successful_store_redirect(response, body, surface)


def analyze_ssrf(response, payload, elapsed_time: float, original_res=None) -> bool:
    if analyze_ssrf_content_proof(response, payload, elapsed_time, original_res):
        return True

    res_text = _extract_response_text(response)
    res_text_lower = res_text.lower()
    original_text = _extract_response_text(original_res) if original_res is not None else ""
    original_text_lower = original_text.lower()
    status_code = _extract_status_code(response)
    original_status_code = _extract_status_code(original_res) if original_res is not None else 0
    payload_value = str(getattr(payload, "value", ""))
    payload_value_lower = payload_value.lower()
    is_cloud_payload = any(hint in payload_value_lower for hint in _CLOUD_TARGET_HINTS)

    # 4) Boolean-blind style delta checks (host discovery, path brute-force, bypasses)
    is_blind_probe = _is_blind_probe_payload(payload_value_lower)
    attack_type = str(getattr(payload, "attack_type", "")).lower()
    is_bypass_or_basic = ("bypass" in attack_type) or ("basic" in attack_type)

    # Cloud-target payloads are intentionally excluded from generic blind length deltas.
    # Cloud success should be confirmed by explicit cloud hints (step 2).
    if (is_blind_probe or is_bypass_or_basic) and original_res is not None and not is_cloud_payload:
        # Reflected include / script-src sinks: body grows or changes because the URL is
        # echoed into HTML, not because the server fetched an internal URL.
        if _probe_url_echoed_in_body(res_text_lower, payload_value_lower):
            pass
        else:
            # 4-1) Status class delta: e.g. baseline 2xx -> probe 4xx/5xx (or inverse)
            if _status_class(status_code) != _status_class(original_status_code):
                return True

            # 4-2) Meaningful body length delta (conservative threshold)
            len_current = len(res_text)
            len_original = len(original_text)
            if len_original > 0:
                diff_ratio = abs(len_current - len_original) / len_original
                if diff_ratio >= 0.30 and abs(len_current - len_original) >= 200:
                    # Drop "empty 200 OK" style responses often caused by silent blocks/failures.
                    if not (status_code == 200 and len_current < 10):
                        return True

            # 4-3) New login page hints (internal admin/login panel reachability)
            has_login_hints = any(hint in res_text_lower for hint in _LOGIN_PAGE_HINTS)
            had_login_hints = any(hint in original_text_lower for hint in _LOGIN_PAGE_HINTS)
            if has_login_hints and not had_login_hints:
                return True

    return _match_time_proof(payload_value_lower, elapsed_time)
