"""정적 JavaScript API 엔드포인트 추출 — 범용 SPA 시딩용"""

from __future__ import annotations

import logging
import os
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from crawler.spa.capture import is_in_scope, record_api_candidate
from crawler.spa.capture_core import path_key_from_url, register_observed_body_field_hints
from parsers.http_method_inference import infer_http_method_from_path
from parsers.body_field_inference import extract_body_field_names_near_url_literal

logger = logging.getLogger(__name__)

# 진단 로그 토글 (환경변수 MWS_DEBUG_JS_ANALYZER=1 로 활성화)
_DEBUG_JS_ANALYZER = os.getenv("MWS_DEBUG_JS_ANALYZER", "").strip() == "1"

MAX_JS_BUNDLE_BYTES = 10 * 1024 * 1024
MAX_INLINE_SCRIPT_BYTES = 512 * 1024
MAX_SCRIPT_SOURCES = 40
MAX_INLINE_SCRIPTS = 40

# === 정적 자산 확장자 (범용 — 사이트 무관) ===
_STATIC_EXTENSIONS = (
    ".css", ".js", ".mjs", ".map", ".json", ".xml", ".txt",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".avif",
    ".mp3", ".mp4", ".webm", ".ogg", ".wav", ".m4a",
    ".pdf", ".zip", ".tar", ".gz", ".rar",
    ".html", ".htm",
)

# === 정규식 패턴 (범용 — API prefix 한정 X) ===

# 절대 URL 또는 절대 경로 리터럴 (최소 3글자 이상의 path)
_URL_LITERAL_PATTERN = (
    r"(?P<quote>['\"`])"
    r"(?P<url>"
        r"(?:https?://[^'\"`\s<>{}|\\^]{4,500})"     # 절대 URL (query 포함 가능)
        r"|"
        # 절대 경로 (최소 3글자). query/encode/템플릿 문자 일부 허용 (`?file=${id}` 등)
        r"(?:/[a-zA-Z][a-zA-Z0-9._~/\\-{}%?=&:$+(),]{2,500})"
    r")"
    r"(?P=quote)"
)

# 1. .METHOD(...) 호출 안에 URL이 들어있는 경우 — minified 코드의 변수 concat 대응
#    예: this.http.post(this.hostServer+"/api/Feedbacks/", body, opts)
_METHOD_CALL_RE = re.compile(
    r"\.(?P<method>get|post|put|patch|delete|head|options)\s*\("
    r"[^)]{0,500}?"
    + _URL_LITERAL_PATTERN,
    re.IGNORECASE | re.DOTALL,
)

# 2. fetch(...) 호출 — options 객체에서 method 추론
_FETCH_CALL_RE = re.compile(
    r"(?<![a-zA-Z_$])fetch\s*\("
    r"[^)]{0,500}?"
    + _URL_LITERAL_PATTERN +
    r"(?P<rest>[^)]{0,400})",
    re.IGNORECASE | re.DOTALL,
)

# 3. fetch options 안의 method 키
_METHOD_IN_OPTIONS_RE = re.compile(
    r"method\s*:\s*['\"`](?P<method>get|post|put|patch|delete|head|options)['\"`]",
    re.IGNORECASE,
)

# 4. Fallback — 따옴표로 감싸진 모든 URL 리터럴 (메서드 못 찾은 경우)
_URL_LITERAL_RE = re.compile(_URL_LITERAL_PATTERN)

# 5. Wrapper helpers (범용): get("/api/x"), post(`/api/x?y=${id}`, data)
_WRAPPER_CALL_RE = re.compile(
    r"(?<![a-zA-Z0-9_$])(?P<wrapper>get|post|postForm|put|patch|del|delete)\s*\("
    r"[^)]{0,600}?"
    + _URL_LITERAL_PATTERN,
    re.IGNORECASE | re.DOTALL,
)


def _placeholder_from_expr(expr: str) -> str:
    """`${var}` 안의 변수명으로 placeholder 종류 추론."""
    lowered = str(expr or "").lower()
    if any(token in lowered for token in ("token", "jwt", "auth", "session", "nonce", "hash", "secret")):
        return "{token}"
    return "{id}"


def _has_static_extension(path_only: str) -> bool:
    """정적 자산 확장자인지 판별 (query/fragment 제거된 path만 검사)."""
    lower = path_only.lower()
    return any(lower.endswith(ext) for ext in _STATIC_EXTENSIONS)


def _normalize_js_url_literal(raw_url: str) -> str | None:
    """JS escape 풀고 placeholder 치환. 노이즈는 None 반환."""
    raw = str(raw_url or "").strip()
    if not raw:
        return None

    # JS escape sequence 정규화
    raw = raw.replace("\\/", "/")
    raw = raw.replace("\\u002f", "/").replace("\\u002F", "/")
    raw = raw.replace("\\x2f", "/").replace("\\x2F", "/")

    # `${var}` → {id}/{token} 휴리스틱
    raw = re.sub(r"\$\{([^}]+)\}", lambda m: _placeholder_from_expr(m.group(1)), raw)

    # `:param` (Express/React Router 스타일) → {id}
    raw = re.sub(r"/:([a-zA-Z_][a-zA-Z0-9_]*)", lambda m: f"/{{{_pick_param_name(m.group(1))}}}", raw)

    # protocol-relative URL
    if raw.startswith("//"):
        raw = "https:" + raw

    # 절대 경로 또는 절대 URL만 채택
    if not (raw.startswith("/") or raw.startswith("http://") or raw.startswith("https://")):
        return None

    # 화이트스페이스/HTML 특수문자 포함 시 거부
    if any(ch in raw for ch in ("<", ">", " ", "\n", "\r", "\t", "\"", "'", "`")):
        return None

    # 정적 자산 확장자 차단 (path 부분만 검사)
    path_part = raw.split("?", 1)[0].split("#", 1)[0]
    if _has_static_extension(path_part):
        return None

    # 너무 짧은 경로 거부 (예: "/", "//", "/a")
    try:
        parsed = urlparse(raw)
        path = parsed.path or ""
        if len(path.strip("/")) < 2:
            return None
    except Exception:
        return None

    return raw


def _pick_param_name(name: str) -> str:
    lowered = str(name or "").lower()
    if any(token in lowered for token in ("token", "jwt", "hash", "secret", "nonce")):
        return "token"
    return "id"


def _infer_content_type(method: str, url: str) -> str:
    """범용적인 content-type 추정 (POST/PUT/PATCH/DELETE는 JSON 가정)."""
    method_upper = str(method).upper()
    if method_upper in ("POST", "PUT", "PATCH", "DELETE"):
        return "application/json"
    return ""


def _content_type_for_wrapper(wrapper: str) -> str:
    w = str(wrapper or "").lower()
    if w == "postform":
        return "multipart/form-data"
    if w in ("post", "put", "patch", "delete", "del"):
        return "application/json"
    return ""


def _extract_from_script_text(script_text: str, *, base_url: str) -> list[tuple[str, str, str]]:
    """JS 텍스트에서 (method, url, content_type) 튜플 리스트 추출."""
    candidates: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    method_matched_urls: set[str] = set()

    # 진단용 카운터 (디버그 모드에서만 사용)
    raw_match_counts = {
        "method_call": 0,
        "fetch_call": 0,
        "wrapper_call": 0,
        "url_literal_fallback": 0,
    }
    rejected_count = 0
    sample_rejected: list[str] = []

    def _append_candidate(method: str, raw_url: str) -> bool:
        nonlocal rejected_count
        normalized = _normalize_js_url_literal(raw_url)
        if not normalized:
            if _DEBUG_JS_ANALYZER:
                rejected_count += 1
                if len(sample_rejected) < 5:
                    sample_rejected.append(raw_url[:80])
            return False
        try:
            resolved = urljoin(base_url, normalized)
        except Exception:
            return False
        content_type = _infer_content_type(method, resolved)
        item = (str(method).upper(), resolved, content_type)
        if item in seen:
            return False
        seen.add(item)
        candidates.append(item)
        return True

    # 1) HTTP 메서드 호출 패턴 (.get/.post/.put/.patch/.delete)
    for match in _METHOD_CALL_RE.finditer(script_text):
        if _DEBUG_JS_ANALYZER:
            raw_match_counts["method_call"] += 1
        url = match.group("url")
        method_matched_urls.add(url)
        _append_candidate(match.group("method"), url)

    # 2) fetch() 호출 — options에서 method 추론, 없으면 GET
    for match in _FETCH_CALL_RE.finditer(script_text):
        if _DEBUG_JS_ANALYZER:
            raw_match_counts["fetch_call"] += 1
        url = match.group("url")
        rest = match.group("rest") or ""
        method_match = _METHOD_IN_OPTIONS_RE.search(rest)
        method = method_match.group("method") if method_match else "GET"
        method_matched_urls.add(url)
        _append_candidate(method, url)

    # 3) Wrapper 호출 — get/post/postForm 등 helper를 HTTP 메서드로 해석
    for match in _WRAPPER_CALL_RE.finditer(script_text):
        if _DEBUG_JS_ANALYZER:
            raw_match_counts["wrapper_call"] += 1
        url = match.group("url")
        wrapper = str(match.group("wrapper") or "").lower()
        method = "DELETE" if wrapper == "del" else wrapper.upper()
        method_matched_urls.add(url)

        normalized = _normalize_js_url_literal(url)
        if not normalized:
            continue
        try:
            resolved = urljoin(base_url, normalized)
        except Exception:
            continue

        content_type = _content_type_for_wrapper(wrapper) or _infer_content_type(method, resolved)
        item = (str(method).upper(), resolved, content_type)
        if item in seen:
            continue
        seen.add(item)
        candidates.append(item)

    # 4) Fallback: 메서드 호출 못 찾은 URL 리터럴은 GET으로 시드
    for match in _URL_LITERAL_RE.finditer(script_text):
        url = match.group("url")
        if url in method_matched_urls:
            continue
        if _DEBUG_JS_ANALYZER:
            raw_match_counts["url_literal_fallback"] += 1
        normalized = _normalize_js_url_literal(url)
        resolved = urljoin(base_url, normalized) if normalized else ""
        method = infer_http_method_from_path(resolved or url)
        _append_candidate(method, url)

    # 진단 출력 (디버그 모드에서만)
    if _DEBUG_JS_ANALYZER:
        if any(raw_match_counts.values()) or candidates:
            logger.debug(
                "[JS-EXTRACT] base=%s size=%d matches=%s candidates=%d rejected=%d",
                base_url, len(script_text), raw_match_counts, len(candidates), rejected_count,
            )
            if sample_rejected:
                logger.debug("[JS-EXTRACT] rejected sample: %s", sample_rejected)
            if candidates:
                logger.debug("[JS-EXTRACT] sample candidates: %s", candidates[:5])
        else:
            logger.debug("[JS-EXTRACT] base=%s (size=%d) — ZERO matches", base_url, len(script_text))

    return candidates


def _extract_scripts_from_html(html_text: str, page_url: str) -> tuple[list[str], list[tuple[str, str]]]:
    soup = BeautifulSoup(html_text, "html.parser")
    script_urls: list[str] = []
    inline_scripts: list[tuple[str, str]] = []
    seen_urls: set[str] = set()

    for script in soup.find_all("script"):
        src = script.get("src")
        if isinstance(src, str) and src.strip():
            resolved = urljoin(page_url, src.strip())
            if resolved not in seen_urls and len(script_urls) < MAX_SCRIPT_SOURCES:
                seen_urls.add(resolved)
                script_urls.append(resolved)
            continue

        inline_text = script.get_text() or ""
        if not inline_text.strip():
            continue
        encoded_size = len(inline_text.encode("utf-8", errors="ignore"))
        if encoded_size > MAX_INLINE_SCRIPT_BYTES:
            inline_text = inline_text[:MAX_INLINE_SCRIPT_BYTES]
        if len(inline_scripts) < MAX_INLINE_SCRIPTS:
            inline_scripts.append((page_url, inline_text))

    return script_urls, inline_scripts


async def _fetch_script_text(context, script_url: str, timeout_ms: int) -> str:
    effective_timeout = min(timeout_ms, 8000)
    try:
        response = await context.request.get(script_url, timeout=effective_timeout)
    except Exception as exc:
        logger.debug("[SPA Crawler] JS fetch timeout for %s: %s", script_url, exc)
        return ""

    if not response.ok:
        return ""

    headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
    content_length = headers.get("content-length", "").strip()
    if content_length.isdigit() and int(content_length) > MAX_JS_BUNDLE_BYTES:
        logger.debug("[SPA Crawler] Skip oversized JS bundle (Content-Length): %s", script_url)
        return ""

    body = await response.body()
    if len(body) > MAX_JS_BUNDLE_BYTES:
        logger.debug("[SPA Crawler] Skip oversized JS bundle (actual bytes): %s", script_url)
        return ""

    return body.decode("utf-8", errors="ignore")


async def seed_api_candidates_from_scripts(engine, page, context) -> int:
    try:
        html_text = await page.content()
    except Exception as exc:
        logger.debug("[SPA Crawler] Failed to read HTML for JS analyzer: %s", exc)
        return 0

    page_url = page.url or getattr(engine, "target_url", "")
    script_urls, inline_scripts = _extract_scripts_from_html(html_text, page_url)
    added = 0

    for base_url, script_text in inline_scripts:
        for method, endpoint_url, content_type in _extract_from_script_text(script_text, base_url=base_url):
            if not is_in_scope(engine, endpoint_url):
                continue
            _, created = record_api_candidate(
                engine,
                method=method,
                url=endpoint_url,
                req_content_type=content_type,
                post_data=None,
                source="js-static",
            )
            if created:
                added += 1
            if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
                near_fields = extract_body_field_names_near_url_literal(script_text, endpoint_url)
                if near_fields:
                    register_observed_body_field_hints(
                        engine,
                        path_key_from_url(urljoin(base_url, endpoint_url)),
                        near_fields,
                    )
        engine.metrics["js_scripts_scanned"] += 1

    timeout_ms = int(getattr(engine, "route_timeout", 5000) or 5000)
    for script_url in script_urls:
        if not is_in_scope(engine, script_url):
            continue
        try:
            script_text = await _fetch_script_text(context, script_url, timeout_ms)
        except Exception as exc:
            logger.debug("[SPA Crawler] JS bundle fetch failed on %s: %s", script_url, exc)
            continue
        if not script_text:
            continue
        for method, endpoint_url, content_type in _extract_from_script_text(script_text, base_url=script_url):
            if not is_in_scope(engine, endpoint_url):
                continue
            _, created = record_api_candidate(
                engine,
                method=method,
                url=endpoint_url,
                req_content_type=content_type,
                post_data=None,
                source="js-static",
            )
            if created:
                added += 1
            if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
                near_fields = extract_body_field_names_near_url_literal(script_text, endpoint_url)
                if near_fields:
                    register_observed_body_field_hints(
                        engine,
                        path_key_from_url(urljoin(script_url, endpoint_url)),
                        near_fields,
                    )
        engine.metrics["js_scripts_scanned"] += 1

    engine.metrics["js_endpoints_seeded"] += added

    return added
