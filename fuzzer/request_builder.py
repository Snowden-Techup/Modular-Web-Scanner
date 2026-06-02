from __future__ import annotations

import asyncio
import copy
import json
import re
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import aiohttp

from core.models import AttackSurface, ParamLocation

from fuzzer.auth_provider import ScanAuthProvider

_DYNAMIC_TOKEN_LOCKS: dict[str, asyncio.Lock] = {}
_auth_provider: ScanAuthProvider | None = None
_DYNAMIC_TOKEN_LOCKS_GUARD = asyncio.Lock()
_HOP_BY_HOP_OR_RESPONSE_HEADERS = {
    "content-length",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "trailer",
    "te",
    "date",
    "server",
    "via",
}

# Names almost always copied from an HTML *response* into crawled AttackSurface.headers.
# Forwarding them on fuzz requests looks like a browser POST but confuses servers and logs.
_CRAWLED_RESPONSE_METADATA_HEADERS = frozenset(
    {
        "content-type",
        "etag",
        "x-powered-by",
        "last-modified",
        "expires",
        "vary",
        "age",
        "cache-control",
        "pragma",
        "cf-ray",
        "cf-cache-status",
        "x-cache",
        "x-served-by",
        "x-frame-options",
        "x-content-type-options",
        "content-security-policy",
        "strict-transport-security",
        "report-to",
        "nel",
        "server-timing",
    }
)

_HEADERS_STRIP_FROM_OUTBOUND = _HOP_BY_HOP_OR_RESPONSE_HEADERS | _CRAWLED_RESPONSE_METADATA_HEADERS

# GraphQL Safe Mode: True이면 Mutation 공격을 스킵.
# CLI/Web에서 set_graphql_safe_mode()로 토글한다.
_GRAPHQL_SAFE_MODE: bool = True


def set_auth_provider(provider: ScanAuthProvider | None) -> None:
    """퍼징 요청마다 적용할 인증 provider (Bearer 갱신·재로그인)."""
    global _auth_provider
    _auth_provider = provider


def get_auth_provider() -> ScanAuthProvider | None:
    return _auth_provider


def set_graphql_safe_mode(enabled: bool) -> None:
    """
    GraphQL Mutation 공격 허용 여부를 설정한다.
    - enabled=True  : 기본. Mutation은 스킵 (DB/상태 변경 방지)
    - enabled=False : Mutation도 공격 (--graphql-unsafe 옵션)
    """
    global _GRAPHQL_SAFE_MODE
    _GRAPHQL_SAFE_MODE = bool(enabled)


def _should_skip_graphql_mutation(gql_type: str) -> bool:
    return _GRAPHQL_SAFE_MODE and gql_type.lower() == "mutation"


def _parse_graphql_surface(surface: AttackSurface) -> tuple[str, str] | None:
    desc = surface.description or ""
    if "GraphQL:" not in desc:
        return None
    try:
        _, gql_type, op_name = desc.split(":", 2)
        return gql_type, op_name
    except ValueError:
        return "query", "unknown"


def _format_graphql_literal(value: Any, type_name: str | None = None) -> str:
    """GraphQL 인자 리터럴 — introspection 타입 힌트 우선, 없으면 값 추론."""
    if value is None:
        return "null"

    if type_name:
        base = type_name.rstrip("!").strip()
        if base.startswith("[") and base.endswith("]"):
            inner = base[1:-1].rstrip("!")
            return f"[{_format_graphql_literal(value, inner)}]"
        if base in ("Int", "ID"):
            text = str(value).strip()
            if re.fullmatch(r"-?\d+", text):
                return text
            return "0"
        if base == "Float":
            text = str(value).strip()
            if re.fullmatch(r"-?\d+(\.\d+)?", text):
                return text
            return "0.0"
        if base == "Boolean":
            text = str(value).strip().lower()
            if text in ("true", "1", "yes"):
                return "true"
            if text in ("false", "0", "no"):
                return "false"
            return "false"
        if base in ("String", "Date", "DateTime", "UUID", "JSON"):
            return json.dumps(str(value))
        # InputObject / enum 등 — 문자열로 전송
        return json.dumps(str(value))

    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(value)

    text = str(value).strip()
    if not text:
        return '""'
    lower = text.lower()
    if lower in ("true", "false"):
        return lower
    if lower == "null":
        return "null"
    if re.fullmatch(r"-?\d+", text):
        return text
    if re.fullmatch(r"-?\d+\.\d+", text):
        return text
    return json.dumps(text)


def _build_graphql_operation_query(
        gql_type: str,
        op_name: str,
        params: dict[str, Any],
        *,
        attack_parameter: str | None = None,
        attack_value: str | None = None,
        arg_types: dict[str, str] | None = None,
) -> str:
    """
    introspection/폼에서 수집한 모든 인자를 포함해 GraphQL operation 문자열 생성.
    attack_parameter가 지정되면 해당 키만 attack_value로 치환한다.
    """
    op_kind = "mutation" if gql_type.lower() == "mutation" else "query"
    type_map = arg_types or {}
    arg_parts: list[str] = []
    for key, val in params.items():
        gql_type_name = type_map.get(str(key))
        if attack_parameter is not None and key == attack_parameter:
            literal = _format_graphql_literal(attack_value, gql_type_name)
        else:
            literal = _format_graphql_literal(val, gql_type_name)
        arg_parts.append(f"{key}: {literal}")

    if arg_parts:
        return f"{op_kind} {{ {op_name}({', '.join(arg_parts)}) {{ __typename }} }}"
    return f"{op_kind} {{ {op_name} {{ __typename }} }}"


@dataclass(slots=True)
class FuzzerResponse:
    """
    Normalized HTTP response passed to vulnerability checkers.
    """

    status: int
    text: str
    headers: dict[str, str]
    elapsed_time: float
    url: str
    error: str | None = None

    @property
    def elapsed(self) -> float:
        """
        Backward-compatible alias.
        Older code may still access `response.elapsed`.
        """
        return self.elapsed_time


class _TokenExtractor(HTMLParser):
    def __init__(self, targets: set[str]) -> None:
        super().__init__()
        self.targets = targets
        self.tokens: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): v for k, v in attrs if v is not None}
        name = attr_map.get("name")
        if not name or name not in self.targets:
            return

        tag_lower = tag.lower()
        if tag_lower == "input":
            value = attr_map.get("value")
            if value is not None:
                self.tokens[name] = value
        elif tag_lower == "meta":
            content = attr_map.get("content")
            if content is not None:
                self.tokens[name] = content


def _dynamic_lock_key(cookies: dict[str, Any]) -> str:
    session_id = cookies.get("PHPSESSID")
    if session_id:
        return f"phpsessid:{session_id}"
    if not cookies:
        return "no-cookie"
    parts = [f"{k}={cookies[k]}" for k in sorted(cookies.keys())]
    return "cookie:" + "|".join(parts)


async def _get_dynamic_token_lock(lock_key: str) -> asyncio.Lock:
    async with _DYNAMIC_TOKEN_LOCKS_GUARD:
        lock = _DYNAMIC_TOKEN_LOCKS.get(lock_key)
        if lock is None:
            lock = asyncio.Lock()
            _DYNAMIC_TOKEN_LOCKS[lock_key] = lock
    return lock


async def fetch_dynamic_tokens(
        session: aiohttp.ClientSession,
        surface: AttackSurface,
        *,
        headers_override: dict[str, Any] | None = None,
        cookies_override: dict[str, Any] | None = None,
) -> dict[str, str]:
    dynamic_tokens = getattr(surface, "dynamic_tokens", None) or {}
    token_targets = {str(token) for token in dynamic_tokens.keys() if str(token)}
    if not token_targets:
        return {}

    headers = copy.deepcopy(headers_override) if headers_override is not None else (
        copy.deepcopy(surface.headers) if surface.headers else {}
    )
    cookies = copy.deepcopy(cookies_override) if cookies_override is not None else (
        copy.deepcopy(surface.cookies) if surface.cookies else {}
    )

    if headers:
        headers = _sanitize_headers_for_request(headers)

    request_kwargs: dict[str, Any] = {}
    if headers:
        request_kwargs["headers"] = headers
    if cookies:
        request_kwargs["cookies"] = cookies

    try:
        async with session.get(surface.url, **request_kwargs) as response:
            html = await response.text(errors="replace")
    except Exception as exc:
        print(f"[request-builder] dynamic token refresh failed: {exc}")
        return {}

    parser = _TokenExtractor(token_targets)
    parser.feed(html)
    return parser.tokens


def _apply_dynamic_tokens(
        tokens: dict[str, str],
        *,
        attack_parameter: str | None,
        req_params: dict[str, Any],
        headers: dict[str, Any],
        cookies: dict[str, Any],
) -> None:
    for token_name, token_value in tokens.items():
        if attack_parameter is not None and token_name == attack_parameter:
            continue
        if token_name in req_params:
            req_params[token_name] = token_value
        if token_name in headers:
            headers[token_name] = token_value
        if token_name in cookies:
            cookies[token_name] = token_value


def _log_dynamic_tokens(
        *,
        surface: AttackSurface,
        attack_parameter: str | None,
        tokens: dict[str, str],
        req_params: dict[str, Any],
        headers: dict[str, Any],
        cookies: dict[str, Any],
) -> None:
    if not tokens:
        return

    mode = "baseline" if attack_parameter is None else f"attack:{attack_parameter}"
    print(f"[*] [DynamicToken] refresh on {surface.url} ({mode})")
    for token_name, extracted_value in tokens.items():
        used_value = None
        used_in = "not-applied"
        if token_name in req_params:
            used_value = req_params[token_name]
            used_in = "params"
        elif token_name in headers:
            used_value = headers[token_name]
            used_in = "headers"
        elif token_name in cookies:
            used_value = cookies[token_name]
            used_in = "cookies"
        print(
            f"    - {token_name}: extracted='{extracted_value}' "
            f"used='{used_value}' location={used_in}"
        )


async def _apply_outbound_auth(
        headers: dict[str, Any],
        cookies: dict[str, Any],
) -> None:
    provider = _auth_provider
    if provider is None:
        return
    await provider.apply(headers, cookies)


async def _send_prepared_request(
        session: aiohttp.ClientSession,
        *,
        method: str,
        url: str,
        request_kwargs: dict[str, Any],
    allow_redirects: bool = True,
) -> FuzzerResponse:
    start_time = time.monotonic()
    try:
        async with session.request(method, url, allow_redirects=allow_redirects, **request_kwargs) as response:
            text = await response.text(errors="replace")
            elapsed = time.monotonic() - start_time
            return FuzzerResponse(
                status=response.status,
                text=text,
                headers=dict(response.headers),
                elapsed_time=elapsed,
                url=str(response.url),
            )
    except asyncio.TimeoutError:
        elapsed = time.monotonic() - start_time
        return FuzzerResponse(
            status=0,
            text="",
            headers={},
            elapsed_time=elapsed,
            url=url,
            error="TimeoutError",
        )
    except aiohttp.ClientError as exc:
        elapsed = time.monotonic() - start_time
        return FuzzerResponse(
            status=0,
            text="",
            headers={},
            elapsed_time=elapsed,
            url=url,
            error=f"ClientError: {exc}",
        )
    except Exception as exc:
        elapsed = time.monotonic() - start_time
        return FuzzerResponse(
            status=0,
            text="",
            headers={},
            elapsed_time=elapsed,
            url=url,
            error=f"UnknownError: {exc}",
        )


async def _send_with_auth_retry(
        session: aiohttp.ClientSession,
        *,
        method: str,
        url: str,
        request_kwargs: dict[str, Any],
        allow_redirects: bool = True,
) -> FuzzerResponse:
    headers = request_kwargs.get("headers")
    if not isinstance(headers, dict):
        headers = {}
        request_kwargs["headers"] = headers
    cookies = request_kwargs.get("cookies")
    if not isinstance(cookies, dict):
        cookies = {}
        request_kwargs["cookies"] = cookies

    await _apply_outbound_auth(headers, cookies)
    response = await _send_prepared_request(
        session,
        method=method,
        url=url,
        request_kwargs=request_kwargs,
        allow_redirects=allow_redirects,
    )
    provider = _auth_provider
    if provider is None or not provider.should_retry_on(response.status):
        return response
    if not await provider.refresh():
        return response

    await _apply_outbound_auth(headers, cookies)
    return await _send_prepared_request(
        session,
        method=method,
        url=url,
        request_kwargs=request_kwargs,
        allow_redirects=allow_redirects,
    )


def _resolve_payload_value(payload: Any) -> str:
    if hasattr(payload, "value"):
        return str(getattr(payload, "value"))
    return str(payload)


def _default_param_seed(name: str) -> str:
    key = str(name or "").strip().lower()
    if not key:
        return "1"
    numeric_hints = ("id", "count", "qty", "price", "amount", "number", "num", "age")
    if any(hint in key for hint in numeric_hints):
        return "1"
    long_text_hints = ("content", "body", "comment", "message", "description", "desc")
    if any(hint in key for hint in long_text_hints):
        return "scanner-seed-content"
    text_hints = ("title", "name", "subject", "keyword", "query", "search")
    if any(hint in key for hint in text_hints):
        return "scanner-seed"
    email_hints = ("email", "mail")
    if any(hint in key for hint in email_hints):
        return "scan@example.com"
    url_hints = ("url", "link", "website", "callback")
    if any(hint in key for hint in url_hints):
        return "https://example.com"
    bool_hints = ("enabled", "active", "is_", "has_", "flag")
    if any(hint in key for hint in bool_hints):
        return "true"
    return "scanner-seed"


def _hydrate_empty_supporting_params(
    params: dict[str, Any],
    *,
    attack_parameter: str,
) -> None:
    """
    Keep injected param untouched, but seed empty sibling fields so mutating
    endpoints can pass basic server-side required checks.
    """
    for key, value in list(params.items()):
        key_str = str(key)
        if key_str == attack_parameter:
            continue
        if value is None or str(value).strip() == "":
            params[key] = _default_param_seed(key_str)


def _sanitize_headers_for_request(headers: dict[str, Any]) -> dict[str, Any]:
    """
    AttackSurface may carry crawled *response* headers.

    Drop hop-by-hop / response metadata so outbound requests resemble a normal
    client: aiohttp sets ``Content-Type`` for form/json/multipart; crawled
    ``Etag``, ``X-Powered-By``, etc. must not be replayed on POST.
    """
    sanitized: dict[str, Any] = {}
    for key, value in headers.items():
        key_lower = str(key).lower()
        if key_lower in _HEADERS_STRIP_FROM_OUTBOUND:
            continue
        sanitized[key] = value
    return sanitized


def _is_file_payload(payload: Any) -> bool:
    return all(
        hasattr(payload, attr)
        for attr in ("filename", "content", "content_type")
    )


def _inject_path_payload(url: str, parameter: str, payload: str) -> str:
    """
    Replace a path placeholder with encoded payload.
    Supported placeholders: {id}, :id
    """
    encoded_payload = quote(payload, safe="")
    brace_token = "{" + parameter + "}"
    colon_token = ":" + parameter

    if brace_token in url:
        return url.replace(brace_token, encoded_payload)
    if colon_token in url:
        return url.replace(colon_token, encoded_payload)
    return url


async def build_and_send_request(
        session: aiohttp.ClientSession,
        surface: AttackSurface,
        parameter: str,
        payload: Any,
    allow_redirects: bool = True
) -> FuzzerResponse:
    """
    Clone attack surface data, inject one payload, and send the HTTP request.
    """
    method = getattr(surface.method, "value", str(surface.method))
    url = surface.url

    req_params = copy.deepcopy(surface.parameters) if surface.parameters else {}
    headers = copy.deepcopy(surface.headers) if surface.headers else {}
    cookies = copy.deepcopy(surface.cookies) if surface.cookies else {}

    if isinstance(req_params, list):
        req_params = {str(k): "" for k in req_params}

    def _apply_lfi_query_url() -> None:
        nonlocal url
        if not (
                is_lfi_payload
                and surface.param_location == ParamLocation.QUERY
                and req_params
        ):
            return
        split_url = urlsplit(url)
        merged_params = dict(parse_qsl(split_url.query, keep_blank_values=True))
        merged_params.update(req_params)
        query_string = urlencode(merged_params, safe="../%:")
        url = urlunsplit(
            (
                split_url.scheme,
                split_url.netloc,
                split_url.path,
                query_string,
                split_url.fragment,
            )
        )
        request_kwargs.pop("params", None)

    request_kwargs: dict[str, Any] = {}
    payload_value = _resolve_payload_value(payload)
    is_file_payload = _is_file_payload(payload)
    is_lfi_payload = type(payload).__name__ == "LFIPayload"
    headers = _sanitize_headers_for_request(headers)

    if surface.param_location == ParamLocation.QUERY:
        req_params[parameter] = payload_value
        if not is_lfi_payload:
            request_kwargs["params"] = req_params
    elif surface.param_location == ParamLocation.BODY_FORM:
        if is_file_payload:
            form = aiohttp.FormData()
            for key, value in req_params.items():
                if key == parameter:
                    continue
                form.add_field(str(key), str(value))
            form.add_field(
                parameter,
                payload.content,
                filename=str(payload.filename),
                content_type=str(payload.content_type),
            )
            request_kwargs["data"] = form
        else:
            req_params[parameter] = payload_value
            _hydrate_empty_supporting_params(req_params, attack_parameter=parameter)
            request_kwargs["data"] = req_params

    #  JSON 및 GraphQL 직렬화 + Safe Mode 방어 (일반 요청)
    elif surface.param_location == ParamLocation.BODY_JSON:
        req_params[parameter] = payload_value
        _hydrate_empty_supporting_params(req_params, attack_parameter=parameter)

        gql_meta = _parse_graphql_surface(surface)
        if gql_meta is not None:
            gql_type, op_name = gql_meta
            if _should_skip_graphql_mutation(gql_type):
                print(f"[Safe Mode] 스킵된 GraphQL Mutation: {op_name} (URL: {url})")
                return FuzzerResponse(
                    status=0, text="", headers={}, elapsed_time=0.0, url=url,
                    error="Skipped by Safe Mode (GraphQL Mutation)"
                )
            query_str = _build_graphql_operation_query(
                gql_type, op_name, req_params,
                attack_parameter=parameter,
                attack_value=payload_value,
                arg_types=getattr(surface, "graphql_arg_types", None) or {},
            )
            request_kwargs["json"] = {"query": query_str}
        else:
            request_kwargs["json"] = req_params

    elif surface.param_location == ParamLocation.HEADER:
        headers[parameter] = payload_value
        if req_params:
            request_kwargs["params"] = req_params
    elif surface.param_location == ParamLocation.COOKIE:
        cookies[parameter] = payload_value
        if req_params:
            request_kwargs["params"] = req_params
    elif surface.param_location == ParamLocation.PATH:
        url = _inject_path_payload(url=url, parameter=parameter, payload=payload_value)
        if req_params:
            request_kwargs["params"] = req_params
    else:
        if req_params:
            request_kwargs["params"] = req_params

    if headers:
        request_kwargs["headers"] = headers
    if cookies:
        request_kwargs["cookies"] = cookies
    _apply_lfi_query_url()
    dynamic_tokens = getattr(surface, "dynamic_tokens", None) or {}
    if not dynamic_tokens:
        return await _send_with_auth_retry(
            session,
            method=method,
            url=url,
            request_kwargs=request_kwargs,
            allow_redirects=allow_redirects,
        )

    lock_key = _dynamic_lock_key(cookies)
    token_lock = await _get_dynamic_token_lock(lock_key)
    async with token_lock:
        new_tokens = await fetch_dynamic_tokens(
            session,
            surface,
            headers_override=headers,
            cookies_override=cookies,
        )
        if new_tokens:
            _apply_dynamic_tokens(
                new_tokens,
                attack_parameter=parameter,
                req_params=req_params,
                headers=headers,
                cookies=cookies,
            )
            _log_dynamic_tokens(
                surface=surface,
                attack_parameter=parameter,
                tokens=new_tokens,
                req_params=req_params,
                headers=headers,
                cookies=cookies,
            )

        if surface.param_location == ParamLocation.QUERY and req_params:
            if not is_lfi_payload:
                request_kwargs["params"] = req_params
        elif surface.param_location == ParamLocation.BODY_FORM:
            if is_file_payload:
                form = aiohttp.FormData()
                for key, value in req_params.items():
                    if key == parameter:
                        continue
                    form.add_field(str(key), str(value))
                form.add_field(
                    parameter,
                    payload.content,
                    filename=str(payload.filename),
                    content_type=str(payload.content_type),
                )
                request_kwargs["data"] = form
            else:
                request_kwargs["data"] = req_params

        #  JSON 및 GraphQL 직렬화 + Safe Mode 방어 (Dynamic Token이 있는 경우)
        elif surface.param_location == ParamLocation.BODY_JSON:
            gql_meta = _parse_graphql_surface(surface)
            if gql_meta is not None:
                gql_type, op_name = gql_meta
                if _should_skip_graphql_mutation(gql_type):
                    print(f"[Safe Mode] 스킵된 GraphQL Mutation: {op_name} (URL: {url})")
                    return FuzzerResponse(
                        status=0, text="", headers={}, elapsed_time=0.0, url=url,
                        error="Skipped by Safe Mode (GraphQL Mutation)"
                    )
                query_str = _build_graphql_operation_query(
                    gql_type, op_name, req_params,
                    attack_parameter=parameter,
                    attack_value=payload_value,
                    arg_types=getattr(surface, "graphql_arg_types", None) or {},
                )
                request_kwargs["json"] = {"query": query_str}
            else:
                request_kwargs["json"] = req_params

        elif req_params:
            request_kwargs["params"] = req_params

        _apply_lfi_query_url()
        if headers:
            request_kwargs["headers"] = headers
        if cookies:
            request_kwargs["cookies"] = cookies

        return await _send_with_auth_retry(
            session,
            method=method,
            url=url,
            request_kwargs=request_kwargs,
            allow_redirects=allow_redirects,
        )


async def send_baseline_request(
        session: aiohttp.ClientSession,
        surface: AttackSurface,
) -> FuzzerResponse:
    """
    Send one non-injected baseline request for comparison analyzers.
    """
    method = getattr(surface.method, "value", str(surface.method))
    url = surface.url

    req_params = copy.deepcopy(surface.parameters) if surface.parameters else {}
    headers = copy.deepcopy(surface.headers) if surface.headers else {}
    cookies = copy.deepcopy(surface.cookies) if surface.cookies else {}

    if isinstance(req_params, list):
        req_params = {str(k): "" for k in req_params}

    headers = _sanitize_headers_for_request(headers)

    request_kwargs: dict[str, Any] = {}

    #  Baseline 요청에도 BODY_JSON, BODY_FORM 위치를 존중하도록 개선
    if surface.param_location == ParamLocation.BODY_JSON:
        gql_meta = _parse_graphql_surface(surface)
        if gql_meta is not None:
            gql_type, op_name = gql_meta
            if _should_skip_graphql_mutation(gql_type):
                print(f"[Safe Mode] 스킵된 GraphQL Baseline Mutation: {op_name} (URL: {url})")
                return FuzzerResponse(
                    status=0, text="", headers={}, elapsed_time=0.0, url=url,
                    error="Skipped by Safe Mode (GraphQL Mutation)"
                )
            query_str = _build_graphql_operation_query(
                gql_type, op_name, req_params,
                arg_types=getattr(surface, "graphql_arg_types", None) or {},
            )
            request_kwargs["json"] = {"query": query_str}
        else:
            request_kwargs["json"] = req_params
    elif surface.param_location == ParamLocation.BODY_FORM:
        request_kwargs["data"] = req_params
    else:
        if req_params:
            request_kwargs["params"] = req_params

    if headers:
        request_kwargs["headers"] = headers
    if cookies:
        request_kwargs["cookies"] = cookies

    dynamic_tokens = getattr(surface, "dynamic_tokens", None) or {}
    if not dynamic_tokens:
        return await _send_with_auth_retry(
            session,
            method=method,
            url=url,
            request_kwargs=request_kwargs,
        )

    lock_key = _dynamic_lock_key(cookies)
    token_lock = await _get_dynamic_token_lock(lock_key)
    async with token_lock:
        new_tokens = await fetch_dynamic_tokens(
            session,
            surface,
            headers_override=headers,
            cookies_override=cookies,
        )
        if new_tokens:
            _apply_dynamic_tokens(
                new_tokens,
                attack_parameter=None,
                req_params=req_params,
                headers=headers,
                cookies=cookies,
            )
            _log_dynamic_tokens(
                surface=surface,
                attack_parameter=None,
                tokens=new_tokens,
                req_params=req_params,
                headers=headers,
                cookies=cookies,
            )

        #  Dynamic Token 이후 Baseline 요청 전송 시 규격 통일
        if surface.param_location == ParamLocation.BODY_JSON:
            gql_meta = _parse_graphql_surface(surface)
            if gql_meta is not None:
                gql_type, op_name = gql_meta
                if _should_skip_graphql_mutation(gql_type):
                    print(f"[Safe Mode] 스킵된 GraphQL Baseline Mutation: {op_name} (URL: {url})")
                    return FuzzerResponse(
                        status=0, text="", headers={}, elapsed_time=0.0, url=url,
                        error="Skipped by Safe Mode (GraphQL Mutation)"
                    )
                query_str = _build_graphql_operation_query(
                    gql_type, op_name, req_params,
                    arg_types=getattr(surface, "graphql_arg_types", None) or {},
                )
                request_kwargs["json"] = {"query": query_str}
            else:
                request_kwargs["json"] = req_params
        elif surface.param_location == ParamLocation.BODY_FORM:
            request_kwargs["data"] = req_params
        else:
            if req_params:
                request_kwargs["params"] = req_params

        if headers:
            request_kwargs["headers"] = headers
        if cookies:
            request_kwargs["cookies"] = cookies

        return await _send_with_auth_retry(
            session,
            method=method,
            url=url,
            request_kwargs=request_kwargs,
        )
