"""HTTP POST body 필드명 추론 — 라벨·경로·JS (앱 고유 vocabulary 없음)."""

from __future__ import annotations

import re

from parsers.http_method_inference import _POST_ACTION_SEGMENTS

__all__ = (
    "infer_field_name_from_label_text",
    "infer_semantic_body_fields_from_path",
    "merge_path_inferred_fields",
    "slugify_field_name",
    "looks_like_url_value",
    "is_plausible_field_name",
    "refine_observed_field_key",
    "sanitize_field_map",
    "extract_body_field_names_from_script",
    "extract_body_field_names_near_url_literal",
)

_NON_WORD_RE = re.compile(r"[^\w\s-]+", re.UNICODE)
_MULTI_SEP_RE = re.compile(r"[\s-]+")
_VALID_FIELD_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_NUMERIC_SEGMENT_RE = re.compile(r"^\d+$|^[0-9a-f]{8,}$", re.I)

# placeholder를 slugify한 흔적 (http_example_com_… 등) — 필드명으로 부적절
_MANGLED_URL_SLUG_RE = re.compile(
    r"(?:^https?_|^http_|_https?_|_http_|(?:^|_)www(?:_|$)|"
    r"example[_-]?com|localhost|\.com_|\.org_|\.net_|://)",
    re.IGNORECASE,
)

# 라벨/aria/placeholder 텍스트 → 필드명 (HTTP·폼 표준 패턴, 앱명 미사용)
_LABEL_SEMANTIC_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?:external|remote|upstream|outbound|foreign|reference|resource|fetch|"
            r"proxy|webhook|callback|redirect|open|embed|avatar|image|logo|photo|"
            r"banner|icon|thumbnail|cover|src|href|"
            r"외부|참조|연동|링크|이미지|가져오)"
            r".{0,40}"
            r"(?:url|uri|link|endpoint|주소|링크)",
            re.IGNORECASE,
        ),
        "external_url",
    ),
    (
        re.compile(
            r"(?:url|uri|link|endpoint|주소|링크)"
            r".{0,40}"
            r"(?:external|remote|reference|fetch|proxy|webhook|callback|foreign|외부|참조)",
            re.IGNORECASE,
        ),
        "external_url",
    ),
    (re.compile(r"^(?:url|uri|link|href|src|endpoint|destination|target)$", re.I), "url"),
    (re.compile(r"\b(?:e-?mail|email_address)\b", re.I), "email"),
    (re.compile(r"\b(?:phone|mobile|tel|telephone|연락|전화)\b", re.I), "phone"),
    (re.compile(r"\b(?:password|passwd|passphrase|비밀)\b", re.I), "password"),
    (re.compile(r"\b(?:username|user_name|login_id|아이디)\b", re.I), "username"),
    (re.compile(r"\b(?:keyword|search_query|검색)\b", re.I), "keyword"),
    (re.compile(r"\b(?:attachment|upload|file_name|첨부|파일)\b", re.I), "attachment"),
    (re.compile(r"\b(?:recipient|수령)\b", re.I), "recipient"),
    (re.compile(r"\b(?:shipping|delivery|배송).{0,20}(?:address|주소)\b", re.I), "address"),
)

_URL_VALUE_RE = re.compile(
    r"^(?:https?://|//|ftp://|file://)[^\s]+$",
    re.IGNORECASE,
)


def looks_like_url_value(text: str) -> bool:
    t = str(text or "").strip()
    if not t or len(t) < 8:
        return False
    return bool(_URL_VALUE_RE.match(t) or "://" in t[:24])


def slugify_field_name(text: str, *, max_len: int = 64) -> str:
    """라벨·placeholder 등을 API 필드명 형태(snake_case)로 정규화."""
    raw = str(text or "").strip()[:80]
    if not raw or looks_like_url_value(raw):
        return ""
    slug = _MULTI_SEP_RE.sub("_", _NON_WORD_RE.sub(" ", raw.lower())).strip("_")[:max_len]
    if slug and _VALID_FIELD_RE.match(slug) and is_plausible_field_name(slug):
        return slug
    return ""


def infer_field_name_from_label_text(label_text: str) -> str:
    """폼 라벨·aria-label·placeholder → 필드명 (HTTP/폼 시맨틱 우선, slug는 보조)."""
    text = str(label_text or "").strip()
    if not text:
        return ""
    if looks_like_url_value(text):
        return "url"
    for pattern, field_name in _LABEL_SEMANTIC_RULES:
        if pattern.search(text):
            return field_name
    return slugify_field_name(text)


def is_plausible_field_name(name: str) -> bool:
    """API body 키로 쓸 수 있는지 (URL placeholder slug 등 제외)."""
    key = str(name or "").strip().lower()
    if not key or not _VALID_FIELD_RE.match(key):
        return False
    if _MANGLED_URL_SLUG_RE.search(key):
        return False
    if len(key) > 40 and key.count("_") >= 3 and ("http" in key or "www" in key):
        return False
    return True


def refine_observed_field_key(
    key: str,
    value: str = "",
    *,
    label: str = "",
) -> str:
    """DOM/추론 키를 정제. 네트워크 관측의 정상 키는 그대로 통과."""
    raw_key = str(key or "").strip()
    if not raw_key:
        return ""
    if is_plausible_field_name(raw_key):
        return raw_key

    hint_parts = [str(label or "").strip()]
    if looks_like_url_value(value):
        hint_parts.append(str(value).strip())
    hint = " ".join(p for p in hint_parts if p).strip()
    inferred = infer_field_name_from_label_text(hint) if hint else ""
    if inferred and is_plausible_field_name(inferred):
        return inferred
    if looks_like_url_value(value) or looks_like_url_value(label):
        return "url"
    return ""


def sanitize_field_map(
    fields: dict[str, str] | None,
    *,
    label_hints: dict[str, str] | None = None,
) -> dict[str, str]:
    """관측 필드 맵에서 비정상 키를 제거·병합하고 시맨틱 키로 대체."""
    if not fields:
        return {}
    hints = label_hints or {}
    cleaned: dict[str, str] = {}
    for raw_key, raw_val in fields.items():
        val = str(raw_val or "")[:500]
        refined = refine_observed_field_key(
            str(raw_key),
            val,
            label=hints.get(str(raw_key), ""),
        )
        if not refined:
            continue
        if refined not in cleaned or (not cleaned[refined] and val):
            cleaned[refined] = val
    return cleaned


def _path_segments(path_key: str) -> tuple[str, ...]:
    return tuple(seg for seg in (path_key or "").lower().split("/") if seg)


def infer_semantic_body_fields_from_path(path_key: str) -> dict[str, str]:
    """경로 형태만으로 placeholder 보강 (앱 vocabulary 없음)."""
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
    merged = sanitize_field_map(existing)
    for key, value in infer_semantic_body_fields_from_path(path_key).items():
        if key not in merged or not str(merged.get(key) or "").strip():
            merged[key] = value
    return merged


# --- JS: FormData.append / JSON body 키 ---

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


def _filter_script_field_names(names: set[str]) -> frozenset[str]:
    return frozenset(n for n in names if is_plausible_field_name(n))


def extract_body_field_names_from_script(script_text: str) -> frozenset[str]:
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

    return _filter_script_field_names(names)


def extract_body_field_names_near_url_literal(
    script_text: str,
    url_literal: str,
    *,
    window: int = 1400,
) -> frozenset[str]:
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
        chunk_start = max(0, idx - half)
        chunk_end = min(len(script_text), idx + half)
        fn_left = script_text.rfind("function ", 0, idx)
        if fn_left >= 0 and fn_left > chunk_start:
            chunk_start = fn_left
        fn_right = script_text.find("function ", idx + 1)
        if fn_right >= 0 and fn_right < chunk_end:
            chunk_end = fn_right
        merged.update(extract_body_field_names_from_script(script_text[chunk_start:chunk_end]))
    return _filter_script_field_names(merged)
