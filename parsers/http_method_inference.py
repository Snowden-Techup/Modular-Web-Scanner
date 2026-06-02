"""URL 경로 기반 HTTP 메서드 및 본문(Body) 파라미터 추론 — 범용 REST/SPA용"""

from __future__ import annotations

from urllib.parse import urlparse

# Final path segments that usually imply a mutating HTTP method.
_POST_ACTION_SEGMENTS = frozenset({
    "add",
    "create",
    "delete",
    "remove",
    "update",
    "edit",
    "write",
    "submit",
    "upload",
    "verify",
    "login",
    "register",
    "logout",
    "confirm",
})

_DEFAULT_PLACEHOLDER = ""


def _path_segments(url: str) -> tuple[str, ...]:
    return tuple(seg.lower() for seg in (urlparse(url).path or "/").split("/") if seg)


def infer_http_method_from_path(url: str) -> str:
    """Infer GET vs POST (etc.) when only a URL literal is known."""
    segments = _path_segments(url)
    if not segments:
        return "GET"
    last = segments[-1]
    if last in _POST_ACTION_SEGMENTS:
        return "POST"
    if len(segments) >= 2 and segments[-2] in ("checkout", "board") and last in ("form", "write"):
        return "POST"
    return "GET"


def infer_body_params_from_path(
    url: str,
    *,
    placeholder: str = _DEFAULT_PLACEHOLDER,
) -> dict[str, str]:
    """Infer POST/PUT body field names from trailing path segments."""
    segments = _path_segments(url)
    if not segments:
        return {}

    if segments[-1] in _POST_ACTION_SEGMENTS:
        return {"id": placeholder}
    return {}


def path_uses_query_params(url: str) -> bool:
    """False when the path shape strongly suggests a request body, not query string."""
    return infer_http_method_from_path(url) == "GET"
