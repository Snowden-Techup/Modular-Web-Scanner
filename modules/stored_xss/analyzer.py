import html
import json
import re
import difflib
import base64
from html.parser import HTMLParser
from typing import List, Optional, Any, Dict, Tuple
from urllib.parse import urlsplit
from bs4 import BeautifulSoup
from core.models import Payload

# =====================================================================
# 상수 및 설정 분리
# =====================================================================
MAX_RESPONSE_LENGTH = 2000000
MAX_PAYLOAD_LENGTH = 10000
OBFUSCATION_THRESHOLD = 0.8

_DANGEROUS_PATTERNS = [
    re.compile(r'on(?:error|load|click|focus|mouseover|start|toggle|begin)\s*=\s*[^\s"\'>=]+', re.I),
    re.compile(r'javascript\s*:[^"\'>\s]{1,1000}', re.I),
    re.compile(r'data\s*:[^"\'>\s]{1,1000}', re.I),
]

_OBFUSCATION_PATTERNS = [
    (re.compile(r'<script[^>]*>([^<]*)</script>', re.I), 'script'),
    (re.compile(r'<[^>]+\s+(on\w+)\s*=', re.I), 'event'),
    (re.compile(r'(javascript)\s*:', re.I), 'protocol'),
    (re.compile(r'<(svg|iframe|object|embed|img)[^>]*>', re.I), 'dangerous_tag'),
]

_FUNC_PATTERNS = [
    re.compile(r'alert\s*\([^)]*\)', re.I),
    re.compile(r'eval\s*\([^)]*\)', re.I),
    re.compile(r'prompt\s*\([^)]*\)', re.I),
    re.compile(r'confirm\s*\([^)]*\)', re.I),
    re.compile(r'atob\s*\([^)]*\)', re.I),
    re.compile(r'document\s*\.\s*cookie', re.I),
    re.compile(r'document\s*\.\s*location', re.I),
]

_ATOB_PATTERN = re.compile(r"atob\s*\(\s*['\"]([^'\"]+)['\"]", re.I)
_JS_COMMENT_SAFE_PATTERN = re.compile(r'/\*[^*]*\*+(?:[^/*][^*]*\*+)*/|//[^\n]*')
_DOM_SINK_PATTERN = re.compile(r'(innerHTML|outerHTML|document\.write|eval|setTimeout|setInterval)\s*\(?\s*[=(]', re.I)

_EXECUTABLE_XSS_PATTERNS = [
    re.compile(r'<script[^>]*>.*?</script>', re.I | re.DOTALL),
    re.compile(r'<[a-zA-Z][^>]*\s+on\w+\s*=\s*["\'][^"\']+["\'][^>]*>', re.I),
    re.compile(r'<[a-zA-Z][^>]*\s+on\w+\s*=\s*[^\s>]+[^>]*>', re.I),
    re.compile(r'<[^>]+(?:href|src|action|formaction|data)\s*=\s*["\']?\s*javascript:[^>]+>', re.I),
    re.compile(r'<(?:svg|img|body|iframe|input|details|marquee)[^>]*\s+on\w+\s*=', re.I),
]


class XSSContextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_script = False
        self.in_textarea = False
        self.in_style = False
        self.in_noscript = False
        self.in_title = False
        self.in_template = False
        self.in_xmp = False
        self.in_iframe = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == 'script':
            self.in_script = True
        elif tag == 'textarea':
            self.in_textarea = True
        elif tag == 'style':
            self.in_style = True
        elif tag == 'noscript':
            self.in_noscript = True
        elif tag == 'title':
            self.in_title = True
        elif tag == 'template':
            self.in_template = True
        elif tag == 'xmp':
            self.in_xmp = True
        elif tag == 'iframe':
            self.in_iframe = True

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == 'script':
            self.in_script = False
        elif tag == 'textarea':
            self.in_textarea = False
        elif tag == 'style':
            self.in_style = False
        elif tag == 'noscript':
            self.in_noscript = False
        elif tag == 'title':
            self.in_title = False
        elif tag == 'template':
            self.in_template = False
        elif tag == 'xmp':
            self.in_xmp = False
        elif tag == 'iframe':
            self.in_iframe = False

    def is_safe_context(self) -> bool:
        return any([
            self.in_textarea, self.in_noscript, self.in_style,
            self.in_title, self.in_template, self.in_xmp, self.in_iframe
        ])


_STRONG_ERROR_SNIPPET_MARKERS = (
    "internal server error",
    "sql syntax",
    "sqlite_error",
    "er_parse_error",
    "syntaxerror",
    "referenceerror",
    "unhandled exception",
    "stack trace",
    "unexpected token",
)

_WEAK_ERROR_SNIPPET_MARKERS = (
    "error",
    "exception",
    "at ",
    "traceback",
)


def response_status(response: Any) -> int:
    try:
        return int(getattr(response, "status_code", getattr(response, "status", 200)) or 200)
    except (TypeError, ValueError):
        return 200


def is_success_status(status: int) -> bool:
    return 200 <= status < 300


def looks_like_error_snippet(text: str) -> bool:
    """에러 페이지·스택 트레이스 본문 — stored XSS 검증에서 제외."""
    if not text:
        return False
    sample = text[:4000].lower()
    if any(marker in sample for marker in _STRONG_ERROR_SNIPPET_MARKERS):
        return True
    weak_hits = sum(1 for marker in _WEAK_ERROR_SNIPPET_MARKERS if marker in sample)
    return weak_hits >= 3


def is_acceptable_verify_response(status: int, body: str, *, marker: str = "") -> bool:
    """2차 검증 GET: 2xx만 허용, 에러 페이지 휴리스틱 적용."""
    if not is_success_status(status):
        return False
    if marker and marker in body:
        idx = body.find(marker)
        start = max(0, idx - 500)
        end = min(len(body), idx + len(marker) + 500)
        if looks_like_error_snippet(body[start:end]):
            return False
    return True


_JSON_CONTENT_TYPES = frozenset(
    {
        "application/json",
        "application/problem+json",
        "application/vnd.api+json",
    }
)

_STORE_API_SUCCESS_KEYS = frozenset(
    {
        "redirect",
        "redirect_url",
        "redirecturl",
        "location",
        "next",
        "continue",
        "id",
        "post_id",
        "item_id",
        "success",
        "ok",
    }
)

_DOM_RENDER_FIELD_HINTS = frozenset(
    {
        "title",
        "content",
        "comment",
        "comments",
        "body",
        "description",
        "name",
        "message",
        "summary",
        "text",
        "html",
        "snippet",
        "bio",
        "caption",
    }
)

# JSON 필드에 <script>만 있어도 innerHTML/v-html 렌더링이 흔한 이름
_SCRIPT_TAG_JSON_FIELD_HINTS = frozenset(
    {
        "title",
        "content",
        "html",
        "body",
        "description",
        "summary",
        "caption",
        "bio",
        "snippet",
    }
)

# 2차 검증: 주입 파라미터와 JSON 필드 경로 매칭 (title 히트로 content 오탐 방지)
_PARAM_JSON_FIELD_ALIASES: dict[str, frozenset[str]] = {
    "content": frozenset({"content", "body", "message", "text", "html", "description"}),
    "body": frozenset({"body", "content", "message", "text", "html"}),
    "comment": frozenset({"comment", "content", "body", "message", "text"}),
    "title": frozenset({"title", "name", "subject", "headline"}),
    "name": frozenset({"name", "title", "username", "author"}),
    "description": frozenset({"description", "desc", "summary", "content", "body"}),
    "message": frozenset({"message", "content", "body", "text"}),
}

_CONTENT_SCRIPT_BLOCK_ANCESTORS = frozenset({"review", "reviews"})
_CONTENT_SCRIPT_ALLOW_ANCESTORS = frozenset(
    {
        "post",
        "posts",
        "board",
        "article",
        "articles",
        "comment",
        "comments",
        "thread",
        "message",
        "messages",
    }
)

# GET 쿼리로 파일/경로를 읽는 엔드포인트 — 저장형이 아닌 반사·LFI 성격
_READ_ONLY_QUERY_PARAM_NAMES = frozenset(
    {
        "file",
        "filename",
        "filepath",
        "path",
        "folder",
        "dir",
        "document",
        "doc",
        "template",
        "page",
        "include",
        "require",
        "log",
        "logfile",
        "lang",
        "locale",
    }
)

_JSON_ERROR_FIELD_SEGMENTS = frozenset(
    {
        "error",
        "errors",
        "err",
        "errmsg",
        "errormessage",
        "error_message",
        "message",
        "detail",
        "reason",
        "exception",
        "stack",
        "stacktrace",
        "trace",
    }
)

_AUTH_FAILURE_PATH_HINTS = ("/login", "/signin", "/auth/login")

_REFLECTED_ONLY_PARAM_NAMES = frozenset(
    {
        "keyword",
        "q",
        "query",
        "term",
        "searchtext",
    }
)

_REFLECTED_ONLY_PATH_SEGMENTS = (
    "/search",
    "/login",
    "/error",
)

_STORE_MUTATION_PATH_HINTS = (
    "write",
    "add",
    "create",
    "comment",
    "edit",
    "update",
    "review",
    "post",
    "reply",
    "submit",
    "register",
    "signup",
)


def _header_content_type(headers: Any) -> str:
    if not headers:
        return ""
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == "content-type":
                return str(value or "").lower()
        return ""
    try:
        return str(headers.get("content-type", "") or headers.get("Content-Type", "")).lower()
    except Exception:
        return ""


def looks_like_json_body(body: str, headers: Any = None) -> bool:
    text = (body or "").strip()
    if not text:
        return False
    header_ct = _header_content_type(headers).split(";", 1)[0].strip()
    if header_ct in _JSON_CONTENT_TYPES or header_ct.endswith("+json"):
        return True
    if text[0] not in "{[":
        return False
    try:
        json.loads(text)
        return True
    except (json.JSONDecodeError, TypeError):
        return False


def _redirect_implies_auth_failure(raw_url: str) -> bool:
    path = (raw_url or "").strip().lower()
    if not path:
        return False
    return any(hint in path for hint in _AUTH_FAILURE_PATH_HINTS)


def surface_expects_json_api(surface: Any) -> bool:
    """SPA/REST API surface인지 (HTML MPA에는 /api/ URL 추론을 쓰지 않음)."""
    for raw in (
        str(getattr(surface, "url", "") or ""),
        str(getattr(surface, "source_url", "") or ""),
    ):
        if "/api/" in raw.lower():
            return True
    for attr in ("request_content_type", "content_type"):
        value = str(getattr(surface, attr, "") or "").lower()
        if "application/json" in value:
            return True
    return False


def is_reflected_only_param(parameter: str) -> bool:
    return str(parameter or "").strip().lower() in _REFLECTED_ONLY_PARAM_NAMES


def is_store_mutation_surface(surface: Any) -> bool:
    path = (urlsplit(str(getattr(surface, "url", "") or "")).path or "").lower()
    return any(hint in path for hint in _STORE_MUTATION_PATH_HINTS)


def _path_suggests_reflected_only(url: str) -> bool:
    path = (urlsplit(url or "").path or "").lower()
    return any(seg in path for seg in _REFLECTED_ONLY_PATH_SEGMENTS)


def is_immediate_reflection_only_hit(
    surface: Any,
    response: Any,
    payload_value: str,
    marker: Optional[str],
) -> bool:
    """
    동일 응답에만 페이로드가 보이고 저장·리다이렉트 신호가 없으면 반사형으로 본다.
    (GET 목록/검색, POST /search 등 — stored_xss verify 부하·오탐 방지)
    """
    body = getattr(response, "text", "") or ""
    if payload_value not in body and not (marker and marker in body):
        return False
    if surface is not None and surface_method_is_get(surface):
        return True
    if surface is not None and not is_store_mutation_surface(surface):
        return True
    response_url = str(getattr(response, "url", "") or "")
    if _path_suggests_reflected_only(response_url):
        return True
    return False


def looks_like_successful_store_redirect(
    response: Any,
    body: str,
    surface: Any,
) -> bool:
    """MPA HTML 폼: POST 저장 후 redirect, 본문에 페이로드가 없는 경우."""
    if surface is None or not is_store_mutation_surface(surface):
        return False
    method = getattr(surface, "method", None)
    raw = getattr(method, "value", method)
    if str(raw or "").upper() not in {"POST", "PUT", "PATCH"}:
        return False
    if not is_success_status(response_status(response)):
        return False
    text = (body or "").strip()
    if text.startswith("{"):
        return False
    final_url = str(getattr(response, "url", "") or "")
    if _redirect_implies_auth_failure(final_url):
        return False
    surface_url = str(getattr(surface, "url", "") or "")
    if not final_url or not surface_url:
        return False
    fin = urlsplit(final_url)
    sur = urlsplit(surface_url)
    if (fin.scheme, fin.netloc, fin.path) == (sur.scheme, sur.netloc, sur.path):
        return False
    return True


def injection_response_implies_failed_auth(response: Any) -> bool:
    final_url = str(getattr(response, "url", "") or "").lower()
    return _redirect_implies_auth_failure(final_url)


def looks_like_successful_store_api_response(response: Any, body: str) -> bool:
    """
  Mutating API가 저장을 수락했지만 본문에 페이로드가 없는 경우(SPA JSON redirect 등).
  2차 GET 검증으로 넘기기 위한 1차 히트 신호.
    """
    if not is_success_status(response_status(response)):
        return False
    text = (body or "").strip()
    if not text.startswith("{"):
        return False
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return False
    if not isinstance(data, dict):
        return False
    error_val = data.get("error")
    if error_val is not None and str(error_val).strip():
        return False
    for key in _STORE_API_SUCCESS_KEYS:
        if key not in data:
            continue
        value = data.get(key)
        if value is None:
            continue
        if key in {"redirect", "redirect_url", "redirecturl", "location", "next", "continue"}:
            raw = str(value).strip()
            if raw and not _redirect_implies_auth_failure(raw):
                return True
            continue
        if key in {"id", "post_id", "item_id"}:
            if str(value).strip():
                return True
            continue
        if key in {"success", "ok"}:
            if value is True or str(value).strip().lower() in {"1", "true", "ok", "success", "yes"}:
                return True
    return False


def _walk_json_marker_hits(
    node: Any,
    marker: str,
    *,
    path: str = "",
    hits: Optional[List[Tuple[str, str]]] = None,
    depth: int = 0,
) -> List[Tuple[str, str]]:
    if hits is None:
        hits = []
    if depth > 12 or not marker:
        return hits
    if isinstance(node, dict):
        for key, value in node.items():
            child_path = f"{path}.{key}" if path else str(key)
            _walk_json_marker_hits(value, marker, path=child_path, hits=hits, depth=depth + 1)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            child_path = f"{path}[{index}]"
            _walk_json_marker_hits(value, marker, path=child_path, hits=hits, depth=depth + 1)
    elif isinstance(node, str) and marker in node:
        hits.append((path or "value", node))
    return hits


def _json_value_suggests_dom_execution(
    value: str,
    marker: str,
    *,
    path: str = "",
) -> bool:
    """
    JSON 문자열 필드만으로 판정할 때: <script> 단독은 React 텍스트 노드 등에서
    실행되지 않는 경우가 많아, 이벤트 핸들러·svg/img 등 강한 신호를 우선한다.
    title/html 등 innerHTML에 가까운 필드명은 <script> 단독도 허용한다.
    """
    if marker not in value:
        return False
    escaped_marker = html.escape(marker)
    if escaped_marker != marker and escaped_marker in value and marker not in value:
        return True
    if "&lt;" in value and marker not in value:
        return False
    if not _check_executable_in_response(value, value, marker).get("executable"):
        return False
    if re.search(r"<script\b", value, re.I):
        if _json_field_path_segments(path) & _SCRIPT_TAG_JSON_FIELD_HINTS:
            return True
        if _content_field_allows_script_tag(path):
            return True
        if re.search(r"\bon\w+\s*=", value, re.I):
            return True
        if re.search(r"<(?:svg|img|iframe|object|embed|math)\b", value, re.I):
            return True
        return False
    return True


def _json_string_stored_unescaped(value: str, marker: str, *, path: str = "") -> bool:
    return _json_value_suggests_dom_execution(value, marker, path=path)


def _content_field_allows_script_tag(path: str) -> bool:
    segments = _json_field_path_segments(path)
    if "content" not in segments:
        return False
    if segments & _CONTENT_SCRIPT_BLOCK_ANCESTORS:
        return False
    return bool(segments & _CONTENT_SCRIPT_ALLOW_ANCESTORS)


def _json_field_path_segments(path: str) -> set[str]:
    segments: set[str] = set()
    for part in re.split(r"\.|\[|\]", path or ""):
        part = str(part).strip().lower()
        if part:
            segments.add(part)
    return segments


def _normalize_verify_location(location: str) -> str:
    raw = str(location or "")
    for prefix in ("json_field_executable:", "json_field_html:"):
        if raw.startswith(prefix):
            return raw[len(prefix):]
    return raw


def verify_context_matches_parameter(parameter: str, location: str) -> bool:
    """
    SPA 목록 API는 title만 내려주고 content는 view API에만 있다.
    주입 파라미터와 검증 위치(JSON 경로)가 맞는지 확인한다.
    """
    param = str(parameter or "").strip().lower()
    if not param:
        return True
    loc = str(location or "")
    if not loc or loc.startswith(("html_", "safe_", "script_", "attribute_", "reflected_only")):
        return True
    if not loc.startswith("json_field_"):
        return True
    path = _normalize_verify_location(loc)
    segments = _json_field_path_segments(path)
    allowed = _PARAM_JSON_FIELD_ALIASES.get(param, frozenset({param}))
    return bool(segments & allowed)


def _json_path_is_error_field(path: str) -> bool:
    return bool(_json_field_path_segments(path) & _JSON_ERROR_FIELD_SEGMENTS)


def _likely_dom_rendered_json_field(path: str) -> bool:
    segments = _json_field_path_segments(path)
    return bool(segments & _DOM_RENDER_FIELD_HINTS)


def surface_method_is_get(surface: Any) -> bool:
    method = getattr(surface, "method", None)
    if method is None:
        return False
    raw = getattr(method, "value", method)
    return str(raw).upper() == "GET"


def is_read_only_query_param(parameter: str) -> bool:
    return str(parameter or "").strip().lower() in _READ_ONLY_QUERY_PARAM_NAMES


def is_get_read_only_surface(surface: Any, parameter: str) -> bool:
    if not surface_method_is_get(surface):
        return False
    loc = getattr(surface, "param_location", None)
    loc_raw = getattr(loc, "value", loc)
    if str(loc_raw or "").lower() not in {"query", "url"}:
        return False
    return is_read_only_query_param(parameter)


def verify_implies_persistent_storage(
    surface: Any,
    injection_url: str,
    hit_url: str,
) -> bool:
    """
    동일 GET 엔드포인트에 마커가 보이는 것만으로는 저장형으로 보지 않는다.
  (파일명·경로 파라미터 반사 / LFI 오류 메시지 등)
    """
    if not surface_method_is_get(surface):
        return True
    inj = urlsplit(injection_url)
    hit = urlsplit(hit_url)
    if (inj.scheme, inj.netloc, inj.path) != (hit.scheme, hit.netloc, hit.path):
        return True
    return False


def analyze_json_stored_context(
    body: str,
    payload_value: str,
    marker: Optional[str] = None,
) -> Dict[str, Any]:
    """JSON API 응답에서 저장된 마커가 실행 가능한 HTML로 내려오는지 판정."""
    search = marker or payload_value
    if not search or search not in body:
        return {"executable": False, "location": "not_reflected"}

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return _analyze_context_robust(body, payload_value, marker)

    hits = _walk_json_marker_hits(data, search)
    if not hits:
        return {"executable": False, "location": "not_reflected"}

    for path, value in hits:
        if _json_path_is_error_field(path):
            continue
        if _is_safely_escaped(value, search):
            continue
        if _json_value_suggests_dom_execution(value, search, path=path):
            exec_check = _check_executable_in_response(value, payload_value, marker)
            location = (
                f"json_field_executable:{path}"
                if exec_check.get("executable")
                else f"json_field_html:{path}"
            )
            return {
                "executable": True,
                "location": location,
                "evidence": (exec_check.get("evidence") or value[:200]),
            }

    return {"executable": False, "location": "json_stored_safe"}


def analyze_verify_response(
    body: str,
    payload_value: str,
    marker: Optional[str] = None,
    *,
    headers: Any = None,
) -> Dict[str, Any]:
    """2차 검증 응답: JSON API vs HTML SSR 자동 분기."""
    if looks_like_json_body(body, headers):
        return analyze_json_stored_context(body, payload_value, marker)
    return _analyze_context_robust(body, payload_value, marker)


def build_verify_request_headers(
    surface: Any,
    check_url: str,
    base_headers: Optional[dict[str, Any]] = None,
) -> dict[str, str]:
    """SPA read API는 JSON Accept를 우선한다 (MPA HTML은 기존 헤더 유지)."""
    headers: dict[str, str] = {}
    for key, value in (base_headers or {}).items():
        if value is not None:
            headers[str(key)] = str(value)
    path = (check_url or "").lower()
    surface_url = str(getattr(surface, "url", "") or "").lower()
    source_url = str(getattr(surface, "source_url", "") or "").lower()
    prefers_json = (
        "/api/" in path
        or path.endswith(".json")
        or "/api/" in surface_url
        or "application/json" in str(getattr(surface, "request_content_type", "") or "").lower()
        or "application/json" in str(getattr(surface, "content_type", "") or "").lower()
    )
    if prefers_json and not source_url.endswith(".html"):
        headers.setdefault("Accept", "application/json")
    return headers


def _is_waf_blocked(response: Any, original_res: Any, baseline_text: Optional[str] = None) -> bool:
    target_status = response_status(response)
    orig_status = response_status(original_res) if original_res else 200

    if target_status in [403, 406, 429, 501, 503] and orig_status < 400:
        return True

    if target_status == 200 and baseline_text and hasattr(response, 'text'):
        current_text = response.text
        if len(current_text) > 0 and len(baseline_text) > 0:
            length_ratio = len(current_text) / len(baseline_text)
            if length_ratio < 0.1:
                return True
            similarity = difflib.SequenceMatcher(None, current_text[:1000], baseline_text[:1000]).ratio()
            if similarity < 0.5:
                return True

    return False


def _is_safely_escaped(body: str, payload_value: str) -> bool:
    """
    페이로드가 HTML 이스케이프되었는지 확인
    """
    if not payload_value:
        return False

    if payload_value in body:
        return False

    escaped_variants = [
        html.escape(payload_value),
        html.escape(payload_value, quote=True),
        payload_value.replace('<', '&lt;').replace('>', '&gt;'),
        payload_value.replace('<', '&#60;').replace('>', '&#62;'),
        payload_value.replace('<', '&#x3c;').replace('>', '&#x3e;'),
        payload_value.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;'),
    ]
    for variant in escaped_variants:
        if variant != payload_value and variant in body:
            return True

    return False


def _extract_injected_marker(payload_value: str) -> Optional[str]:
    """페이로드 문자열에서 주입된 고유 마커(xss_xxxxxx)를 추출합니다."""
    # 1. 평문 탐색 (xss_a1b2c3)
    match = re.search(r"xss_[a-f0-9]{6}", payload_value)
    if match: return match.group(0)

    # 2. Base64 디코딩 후 탐색
    b64_matches = re.findall(r"atob\(['\"]([A-Za-z0-9+/=]+)['\"]\)", payload_value)
    for b64 in b64_matches:
        try:
            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
            m = re.search(r"xss_[a-f0-9]{6}", decoded)
            if m: return m.group(0)
        except Exception:
            continue

    # 3. String.fromCharCode 디코딩 후 탐색
    char_matches = re.findall(r"fromCharCode\(([\d,\s]+)\)", payload_value)
    for char_str in char_matches:
        try:
            chars = [int(c.strip()) for c in char_str.split(",")]
            decoded = "".join(chr(c) for c in chars)
            m = re.search(r"xss_[a-f0-9]{6}", decoded)
            if m: return m.group(0)
        except Exception:
            continue
    return None


def _check_executable_in_response(body: str, payload_value: str, marker: Optional[str] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "executable": False,
        "evidence": None,
        "pattern_type": None
    }

    if payload_value not in body and (marker and marker not in body):
        return result

    payload_idx = body.find(payload_value)
    if payload_idx == -1 and marker:
        payload_idx = body.find(marker)

    unique_markers = [marker] if marker else _extract_unique_markers(payload_value)

    # 🌟 [개선 1] lxml 파서 우선 사용 및 html.parser 폴백
    try:
        soup = BeautifulSoup(body, 'lxml')
    except Exception:
        soup = BeautifulSoup(body, 'html.parser')

    try:
        for m in unique_markers:
            if not m: continue

            m_lower = m.lower()

            # 🌟 [개선 2] 단순히 속성 값이 아닌, "실행 가능한 속성"인지 엄격하게 검증
            def is_executable_attr_injection(tag):
                for attr_name, attr_val in tag.attrs.items():
                    attr_val_str = str(attr_val).lower()

                    if m_lower in attr_val_str:
                        if attr_name.lower().startswith('on'):
                            return True
                        if attr_name.lower() in ['href', 'src', 'action', 'formaction', 'data']:
                            if 'javascript:' in attr_val_str:
                                return True
                return False

            suspect_tags = soup.find_all(is_executable_attr_injection)
            if suspect_tags:
                result["executable"] = True
                result["evidence"] = str(suspect_tags[0])[:200]
                result["pattern_type"] = "bs4_dom_attribute_injection (Event/URI Protocol)"
                return result

            script_tags = soup.find_all('script', string=re.compile(m, re.I))
            if script_tags:
                result["executable"] = True
                result["evidence"] = str(script_tags[0])[:200]
                result["pattern_type"] = "bs4_dom_script_injection"
                return result
    except Exception:
        pass

    if soup.find() is not None:
        return result

    for pattern in _EXECUTABLE_XSS_PATTERNS:
        matches = pattern.finditer(body)
        for match in matches:
            matched_str = match.group(0)
            is_related = False

            if payload_value in matched_str:
                is_related = True

            for m in unique_markers:
                if m and m.lower() in matched_str.lower():
                    is_related = True
                    break

            match_start = match.start()
            match_end = match.end()
            payload_end = payload_idx + len(payload_value)

            if (match_start <= payload_idx <= match_end) or (match_start <= payload_end <= match_end):
                is_related = True

            if is_related:
                result["executable"] = True
                result["evidence"] = matched_str[:200]
                result["pattern_type"] = pattern.pattern[:50]
                return result

    return result


def _extract_unique_markers(payload: str) -> List[str]:
    """페이로드에서 고유 식별 가능한 문자열 추출"""
    markers = []

    string_matches = re.findall(r'["\']([^"\']{2,30})["\']', payload)
    markers.extend(string_matches)

    func_matches = re.findall(r'(alert|prompt|confirm|eval)\s*\(', payload, re.I)
    markers.extend(func_matches)

    event_matches = re.findall(r'(on\w+)\s*=', payload, re.I)
    markers.extend(event_matches)

    return list(set(m for m in markers if m and len(m) >= 2))


def _analyze_context_robust(body: str, payload_value: str, marker: Optional[str] = None) -> Dict[str, Any]:
    """
    페이로드가 위치한 정확한 컨텍스트를 파악합니다. (오탐 방지 개선 로직 적용)
    """
    payload_idx = body.find(payload_value)

    if payload_idx == -1:
        if marker and marker in body:
            payload_idx = body.find(marker)
        else:
            return {"executable": False, "location": "not_reflected"}

    try:
        soup = BeautifulSoup(body, 'lxml')
        texts = soup.find_all(string=True)
        for text_node in texts:
            if payload_value in text_node or (marker and marker in text_node):
                parent_tag = text_node.parent.name if text_node.parent else ""
                if parent_tag not in ['script', 'style', 'iframe']:
                    return {"executable": False, "location": "safe_text_node"}
    except Exception:
        pass

    html_before_payload = body[:payload_idx]
    recent_html = html_before_payload[-500:] if len(html_before_payload) > 500 else html_before_payload

    last_open_tag = recent_html.rfind('<')
    last_close_tag = recent_html.rfind('>')

    if last_open_tag != -1 and last_open_tag > last_close_tag:
        tag_content = recent_html[last_open_tag:]
        single_quotes = tag_content.count("'")
        double_quotes = tag_content.count('"')

        last_single = tag_content.rfind("'")
        last_double = tag_content.rfind('"')

        in_single_quote = single_quotes % 2 != 0 and last_single > last_double
        in_double_quote = double_quotes % 2 != 0 and last_double > last_single

        if in_single_quote or in_double_quote:
            quote_char = "'" if in_single_quote else '"'

            is_js_attr = re.search(r"\b(on\w+|href|src|action|formaction)\s*=\s*['\"]$", tag_content, re.I)
            if is_js_attr:
                return {"executable": True, "location": "js_attribute_value"}

            if quote_char in payload_value or '>' in payload_value:
                return {"executable": True, "location": "attribute_breakout"}
            else:
                exec_check = _check_executable_in_response(body, payload_value, marker)
                if exec_check["executable"]:
                    return {
                        "executable": True,
                        "location": "html_body_executable (recovered from attribute trap)",
                        "evidence": exec_check["evidence"]
                    }
                return {"executable": False, "location": "attribute_trapped"}

    parser = XSSContextParser()
    try:
        parser.feed(html_before_payload[-2000:])
    except Exception:
        pass

    if parser.is_safe_context():
        return {"executable": False, "location": "safe_tag"}

    if parser.in_script:
        script_start_idx = html_before_payload.rfind('<script')
        if script_start_idx != -1:
            js_content = body[script_start_idx:payload_idx]
            clean_js = _JS_COMMENT_SAFE_PATTERN.sub('', js_content)

            single_quotes = clean_js.count("'") - clean_js.count("\\'")
            double_quotes = clean_js.count('"') - clean_js.count('\\"')
            backticks = clean_js.count('`') - clean_js.count('\\`')

            in_string = (single_quotes % 2 != 0) or (double_quotes % 2 != 0) or (backticks % 2 != 0)

            if in_string:
                if any(c in payload_value for c in ["'", '"', '`', '</script', '\\n', '\\r']):
                    return {"executable": True, "location": "script_string_breakout"}
                else:
                    return {"executable": False, "location": "script_string_trapped"}
            else:
                return {"executable": True, "location": "script_code_area"}

    exec_check = _check_executable_in_response(body, payload_value, marker)
    if exec_check["executable"]:
        return {
            "executable": True,
            "location": "html_body_executable",
            "evidence": exec_check["evidence"]
        }

    return {"executable": False, "location": "html_body_filtered"}


def _check_partial_escape(body: str, payload_value: str, marker: Optional[str] = None) -> bool:
    """위험한 패턴이 부분적으로 이스케이프를 우회했는지 확인"""
    for pattern in _DANGEROUS_PATTERNS:
        matches = pattern.findall(payload_value)
        for match in matches:
            if match in body:
                escaped = html.escape(match)
                if escaped != match and escaped not in body:
                    context_state = _analyze_context_robust(body, match, marker)
                    if context_state["executable"]:
                        return True
    return False


def _check_obfuscated_reflection(body: str, payload_value: str, baseline: Optional[str] = None) -> bool:
    """난독화되거나 변형된 페이로드가 실행 가능하게 반사되었는지 확인"""
    body_lower = body.lower()
    baseline_lower = baseline.lower() if baseline else ""

    for pattern, pattern_type in _OBFUSCATION_PATTERNS:
        current_matches = pattern.findall(body_lower)
        if not current_matches:
            continue

        baseline_matches = pattern.findall(baseline_lower) if baseline else []

        if len(current_matches) > len(baseline_matches):
            payload_markers = _extract_unique_markers(payload_value)
            for match in current_matches:
                match_str = match if isinstance(match, str) else str(match)
                for marker in payload_markers:
                    if marker.lower() in match_str.lower():
                        return True

    fragments = _extract_payload_fragments(payload_value)
    for fragment in fragments:
        fragment_lower = fragment.lower()

        current_count = body_lower.count(fragment_lower)
        baseline_count = baseline_lower.count(fragment_lower) if baseline else 0

        if current_count > baseline_count:
            for match in re.finditer(re.escape(fragment_lower), body_lower):
                fragment_idx = match.start()
                start = max(0, fragment_idx - 50)
                end = min(len(body_lower), fragment_idx + len(fragment) + 50)
                surrounding = body_lower[start:end]

                if re.search(
                        r'<script[^>]*>|on\w+\s*=\s*["\']|(?:href|src|action|formaction)\s*=\s*["\']?\s*javascript:',
                        surrounding, re.I):
                    return True

    return False


def _extract_payload_fragments(payload: str) -> List[str]:
    """페이로드에서 위험한 함수 호출 패턴 추출"""
    fragments = []
    for pattern in _FUNC_PATTERNS:
        fragments.extend(pattern.findall(payload))
    fragments.extend(_ATOB_PATTERN.findall(payload))
    return list(set(f for f in fragments if len(f) >= 4))


def analyze_stored_xss(
        response: Any,
        payload: Payload,
        elapsed_time: float,
        original_res: Any = None,
        requester: Any = None,
        baseline: Optional[str] = None,
        surface: Any = None,
) -> Dict[str, Any]:
    """
    [범용] Stored XSS 취약점 분석
    """
    _ = requester

    result = {
        "is_vulnerable": False,
        "context": "unknown",
        "evidence": "",
        "waf_blocked": False,
        "needs_manual_dom_review": False,
        "elapsed_time": elapsed_time
    }

    if not response or not hasattr(response, 'text') or not response.text:
        result["context"] = "no_response"
        return result

    # 쿼리스트링 URL + 5xx: 에러 페이지 반사 가능성이 높아 1차 분석 스킵 (verify 부하 감소)
    injection_status = response_status(response)
    response_url = str(getattr(response, "url", "") or "")
    if injection_status >= 500 and "?" in response_url:
        result["context"] = "server_error_query"
        result["evidence"] = (
            f"Query injection returned HTTP {injection_status}; skipping (likely error reflection)"
        )
        return result

    response_body = response.text[:MAX_RESPONSE_LENGTH]
    payload_value = (payload.value or "")[:MAX_PAYLOAD_LENGTH] if payload.value else ""

    if not payload_value:
        result["context"] = "empty_payload"
        return result

    marker = _extract_injected_marker(payload_value)

    if _is_waf_blocked(response, original_res, baseline):
        result["waf_blocked"] = True
        result["context"] = "waf_blocked"
        return result

    if _DOM_SINK_PATTERN.search(response_body):
        result["needs_manual_dom_review"] = True

    if _is_safely_escaped(response_body, payload_value):
        result["context"] = "safely_escaped"
        result["evidence"] = "Payload was HTML-escaped"
        return result

    response_headers = getattr(response, "headers", None)

    if payload_value in response_body or (marker and marker in response_body):
        if is_immediate_reflection_only_hit(surface, response, payload_value, marker):
            result["context"] = "reflected_only_not_stored"
            result["evidence"] = (
                "Inline reflection on read/search surface; deferred to reflected_xss / skip stored verify"
            )
            return result

        if looks_like_json_body(response_body, response_headers):
            context_state = analyze_json_stored_context(response_body, payload_value, marker)
        else:
            context_state = _analyze_context_robust(response_body, payload_value, marker)

        result["context"] = context_state["location"]

        if context_state["executable"]:
            result["is_vulnerable"] = True
            result["evidence"] = f"Payload reflected in executable context: {context_state['location']}"
            if "evidence" in context_state:
                result["evidence"] += f" | {context_state['evidence'][:100]}"
            return result
        else:
            result["evidence"] = f"Payload reflected but not executable ({context_state['location']})"
            return result

    if _check_partial_escape(response_body, payload_value, marker):
        result["is_vulnerable"] = True
        result["context"] = "partial_escape_bypass"
        result["evidence"] = "Dangerous handlers bypassed escaping"
        return result

    baseline_body = baseline[:MAX_RESPONSE_LENGTH] if baseline else None
    if _check_obfuscated_reflection(response_body, payload_value, baseline_body):
        result["is_vulnerable"] = True
        result["context"] = "obfuscated_reflection"
        result["evidence"] = "Payload fragments reflected in executable context"
        return result

    if looks_like_successful_store_api_response(response, response_body):
        result["is_vulnerable"] = True
        result["context"] = "stored_api_deferred_verify"
        result["evidence"] = (
            "Mutating API accepted request without inline reflection; "
            "deferred to read-endpoint verification"
        )
        return result

    if looks_like_successful_store_redirect(response, response_body, surface):
        result["is_vulnerable"] = True
        result["context"] = "stored_redirect_deferred_verify"
        result["evidence"] = (
            "Mutating form accepted request and redirected without inline reflection; "
            "deferred to read-endpoint verification"
        )
        return result

    result["context"] = "filtered_or_not_reflected"
    result["evidence"] = "Payload not found in response"

    if result["needs_manual_dom_review"] and not result["is_vulnerable"]:
        result["evidence"] = "Payload filtered, but DOM sinks detected. Manual review recommended."

    return result