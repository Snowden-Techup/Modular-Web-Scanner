"""HTTP POST body 필드명 추론 — 라벨 슬러그, 경로 형태, 번들 JS 정적 추출."""

from __future__ import annotations

import re

from parsers.http_method_inference import _POST_ACTION_SEGMENTS

__all__ = (
    "infer_field_name_from_label_text",
    "infer_semantic_body_fields_from_path",
    "merge_path_inferred_fields",
    "slugify_field_name",
    "extract_body_field_names_from_script",
    "extract_body_field_names_near_url_literal",
)

_NON_WORD_RE = re.compile(r"[^\w\s-]+", re.UNICODE)
_MULTI_SEP_RE = re.compile(r"[\s-]+")
_VALID_FIELD_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_NUMERIC_SEGMENT_RE = re.compile(r"^\d+$|^[0-9a-f]{8,}$", re.I)


def slugify_field_name(text: str, *, max_len: int = 64) -> str:
    """라벨·placeholder 등을 API 필드명 형태(snake_case)로 정규화."""
    raw = str(text or "").strip()[:80]
    if not raw:
        return ""
    slug = _MULTI_SEP_RE.sub("_", _NON_WORD_RE.sub(" ", raw.lower())).strip("_")[:max_len]
    if slug and _VALID_FIELD_RE.match(slug):
        return slug
    return ""


def infer_field_name_from_label_text(label_text: str) -> str:
    """폼 라벨·aria-label·placeholder → 필드명 후보 (시맨틱 추측 없음)."""
    return slugify_field_name(label_text)


def _path_segments(path_key: str) -> tuple[str, ...]:
    return tuple(seg for seg in (path_key or "").lower().split("/") if seg)


def infer_semantic_body_fields_from_path(path_key: str) -> dict[str, str]:
    """
    XHR/폼 관측이 없을 때 경로 형태만으로 placeholder 필드명을 보강한다.
    앱별 vocabulary(게시판·주문 등)는 사용하지 않는다.
    """
    segments = _path_segments(path_key)
    if not segments:
        return {}

    fields: dict[str, str] = {}
    if segments[-1] in _POST_ACTION_SEGMENTS:
        fields.setdefault("id", "")
    if any(_NUMERIC_SEGMENT_RE.match(seg) for seg in segments):
        fields.setdefault("id", "")
    return fields


def merge_path_inferred_fields(
    existing: dict[str, str] | None,
    path_key: str,
) -> dict[str, str]:
    """관측·DOM·XHR 필드는 유지하고, 비어 있는 키만 경로 형태 힌트로 채운다."""
    merged = dict(existing or {})
    for key, value in infer_semantic_body_fields_from_path(path_key).items():
        if key not in merged or not str(merged.get(key) or "").strip():
            merged[key] = value
    return merged


# --- 번들/인라인 JS에서 request body 필드명 추출 ---

_FORM_DATA_APPEND_RE = re.compile(
    r"\.append\s*\(\s*['\"`](?P<field>[a-zA-Z_][a-zA-Z0-9_]*)['\"`]\s*,",
    re.IGNORECASE,
)

_JSON_BODY_LITERAL_RE = re.compile(
    r"(?:\bpost|\bput|\bpatch)\s*\(\s*[^,]{0,400}?,\s*\{([^}]{0,3000})\}",
    re.IGNORECASE | re.DOTALL,
)

_JSON_OBJECT_KEY_RE = re.compile(
    r"(?:['\"`](?P<qfield>[a-zA-Z_][a-zA-Z0-9_]*)['\"`]|(?P<bare>[a-zA-Z_][a-zA-Z0-9_]*))\s*:",
)

_SKIP_FIELD_NAMES = frozenset(
    {
        "headers",
        "method",
        "body",
        "credentials",
        "mode",
        "cache",
        "redirect",
        "signal",
        "then",
        "catch",
    }
)


def extract_body_field_names_from_script(script_text: str) -> frozenset[str]:
    """SPA 번들에서 관측 가능한 body 필드명 집합 (사이트 무관 패턴)."""
    if not script_text:
        return frozenset()

    names: set[str] = set()
    for match in _FORM_DATA_APPEND_RE.finditer(script_text):
        field = str(match.group("field") or "").strip()
        if field and field.lower() not in _SKIP_FIELD_NAMES:
            names.add(field)

    for block in _JSON_BODY_LITERAL_RE.finditer(script_text):
        fragment = block.group(1) or ""
        for key_match in _JSON_OBJECT_KEY_RE.finditer(fragment):
            field = str(key_match.group("qfield") or key_match.group("bare") or "").strip()
            if field and field.lower() not in _SKIP_FIELD_NAMES:
                names.add(field)

    return frozenset(names)


def extract_body_field_names_near_url_literal(
    script_text: str,
    url_literal: str,
    *,
    window: int = 1400,
) -> frozenset[str]:
    """
    번들 전역이 아니라 URL 리터럴 인접 구간에서만 필드명을 추출한다.
    (한 chunk에 여러 feature가 있어도 엔드포인트별로 분리)
    """
    if not script_text or not url_literal:
        return frozenset()

    needle = str(url_literal).strip()
    if not needle:
        return frozenset()

    positions: list[int] = []
    start = 0
    while True:
        idx = script_text.find(needle, start)
        if idx < 0:
            break
        positions.append(idx)
        start = idx + max(1, len(needle))
        if len(positions) >= 6:
            break

    if not positions:
        path_only = needle.split("?", 1)[0].rstrip("/")
        if path_only and path_only != needle:
            return extract_body_field_names_near_url_literal(
                script_text, path_only, window=window
            )
        return frozenset()

    merged: set[str] = set()
    half = max(200, window // 2)
    for idx in positions:
        start = max(0, idx - half)
        end = min(len(script_text), idx + half)
        fn_left = script_text.rfind("function ", 0, idx)
        if fn_left >= 0 and fn_left > start:
            start = fn_left
        fn_right = script_text.find("function ", idx + 1)
        if fn_right >= 0 and fn_right < end:
            end = fn_right
        merged.update(extract_body_field_names_from_script(script_text[start:end]))
    return frozenset(merged)
