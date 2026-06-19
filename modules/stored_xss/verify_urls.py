"""
Stored XSS 2차 검증용 후보 URL 수집 (앱/게시판 하드코딩 없음).

우선순위:
1. 주입 응답 최종 URL · Location/Refresh 헤더
2. 응답 HTML/JSON에서 상세·목록 페이지 링크 (공통 패턴)
3. 폼 surface / source / Referer / 관련 상위 경로
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from modules.file_upload.path_discovery import (
    extract_post_detail_urls,
    iter_related_crawl_urls,
)
from modules.stored_xss.analyzer import surface_expects_json_api

_JSON_URL_KEYS = frozenset(
    {
        "url",
        "uri",
        "link",
        "href",
        "path",
        "location",
        "redirect",
        "redirecturl",
        "redirect_url",
        "next",
        "continue",
    }
)

_REFRESH_URL_RE = re.compile(r"url\s*=\s*['\"]?([^;'\"]+)", re.IGNORECASE)

_MUTATION_PATH_SUFFIXES = (
    "/write",
    "/add",
    "/create",
    "/post",
    "/comment",
    "/edit",
    "/update",
    "/reply",
    "/process",
    "/confirm",
    "/submit",
    "/complete",
)

# 결제·주문류 mutation 후 상세 조회가 다른 컬렉션에 있는 SPA/REST 패턴
_MUTATION_TO_READ_COLLECTIONS: dict[str, tuple[str, ...]] = {
    "checkout": ("orders", "order"),
    "payment": ("orders", "order", "payments"),
    "cart": ("orders",),
    "purchase": ("orders", "order"),
}

_COLLECTION_ARRAY_KEYS = frozenset(
    {
        "posts",
        "orders",
        "items",
        "results",
        "entries",
        "articles",
        "threads",
        "comments",
        "books",
        "records",
        "rows",
        "data",
    }
)

_READ_PATH_SUFFIXES = (
    "/view",
    "/detail",
    "/show",
    "/read",
    "/get",
)

_ID_FIELD_NAMES = frozenset(
    {
        "id",
        "post_id",
        "item_id",
        "book_id",
        "article_id",
        "thread_id",
        "comment_id",
    }
)


def _append_unique(ordered: list[str], seen: set[str], raw_url: str) -> None:
    url = (raw_url or "").strip()
    if not url or url in seen:
        return
    seen.add(url)
    ordered.append(url)


def _normalize_absolute(base_url: str, raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if raw.startswith(("http://", "https://")):
        return raw
    if raw.startswith("//"):
        split = urlsplit(base_url)
        if split.scheme:
            return f"{split.scheme}:{raw}"
        return raw
    return urljoin(base_url, raw)


def _location_from_headers(headers: dict[str, Any] | None, base_url: str) -> list[str]:
    if not headers:
        return []
    found: list[str] = []
    for key, value in headers.items():
        if not value:
            continue
        key_lower = str(key).lower()
        if key_lower == "location":
            found.append(_normalize_absolute(base_url, str(value)))
        elif key_lower == "refresh":
            match = _REFRESH_URL_RE.search(str(value))
            if match:
                found.append(_normalize_absolute(base_url, match.group(1)))
    return [u for u in found if u]


def _urls_from_json(node: Any, base_url: str, found: set[str], *, depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            key_lower = str(key).lower()
            if key_lower in _JSON_URL_KEYS and isinstance(value, str) and value.strip():
                found.add(_normalize_absolute(base_url, value))
            else:
                _urls_from_json(value, base_url, found, depth=depth + 1)
    elif isinstance(node, list):
        for item in node:
            _urls_from_json(item, base_url, found, depth=depth + 1)


def _scheme_netloc(base_url: str) -> tuple[str, str]:
    split = urlsplit(base_url or "")
    if split.scheme and split.netloc:
        return split.scheme, split.netloc
    return "", ""


def _client_route_to_api_url(route_url: str, base_url: str) -> str:
    """`/board/view?id=1` -> `/api/board/view?id=1` (범용 SPA 라우트 매핑)."""
    raw = (route_url or "").strip()
    if not raw:
        return ""
    split = urlsplit(raw)
    if not split.scheme or not split.netloc:
        scheme, netloc = _scheme_netloc(base_url)
        if not scheme or not netloc:
            return ""
        split = urlsplit(urljoin(f"{scheme}://{netloc}", raw))
    path = split.path or ""
    if "/api/" in path.lower():
        return urlunsplit((split.scheme, split.netloc, path, split.query, ""))
    parts = [part for part in path.split("/") if part]
    if not parts:
        return ""
    api_path = "/api/" + "/".join(parts)
    return urlunsplit((split.scheme, split.netloc, api_path, split.query, ""))


def _view_template_from_mutation_url(url: str) -> str | None:
    split = urlsplit(url or "")
    path = split.path or ""
    lower = path.lower()
    for suffix in _MUTATION_PATH_SUFFIXES:
        if lower.endswith(suffix):
            stem = path[: -len(suffix)]
            if not stem:
                return None
            return urlunsplit((split.scheme, split.netloc, f"{stem}/view", "", ""))
    return None


def _list_template_from_mutation_url(url: str) -> str | None:
    split = urlsplit(url or "")
    path = split.path or ""
    lower = path.lower()
    for suffix in _MUTATION_PATH_SUFFIXES:
        if lower.endswith(suffix):
            stem = path[: -len(suffix)]
            if not stem:
                return None
            return urlunsplit((split.scheme, split.netloc, stem, "", ""))
    return None


def _api_path_segments(url: str) -> list[str]:
    path = (urlsplit(url or "").path or "").lower()
    return [seg for seg in path.split("/") if seg and seg != "api"]


def _infer_read_urls_for_collection(
    base_url: str,
    collection_name: str,
    *,
    query: str = "",
) -> list[str]:
    """``orders`` -> ``/api/orders``, ``/api/orders/view`` (+ optional query)."""
    scheme, netloc = _scheme_netloc(base_url)
    if not scheme or not netloc or not collection_name:
        return []
    stem = f"/api/{collection_name.strip('/')}"
    list_path = stem
    view_path = f"{stem}/view"
    if query:
        list_url = urlunsplit((scheme, netloc, list_path, query, ""))
        view_url = urlunsplit((scheme, netloc, view_path, query, ""))
    else:
        list_url = urlunsplit((scheme, netloc, list_path, "", ""))
        view_url = urlunsplit((scheme, netloc, view_path, "", ""))
    return [list_url, view_url]


def infer_related_read_api_urls(
    surface: Any,
    base_url: str,
    injection_body: str = "",
) -> list[str]:
    """
    mutation·redirect 맥락에서 '다른 컬렉션' read API를 추론 (checkout -> orders/view 등).
    """
    found: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        normalized = _normalize_absolute(base_url, raw)
        if normalized and normalized not in seen:
            seen.add(normalized)
            found.append(normalized)

    for raw in (
        str(getattr(surface, "url", "") or ""),
        str(getattr(surface, "source_url", "") or ""),
    ):
        for seg in _api_path_segments(raw):
            for collection in _MUTATION_TO_READ_COLLECTIONS.get(seg, ()):
                for url in _infer_read_urls_for_collection(base_url, collection):
                    add(url)

    for redirect_url in extract_redirect_urls_from_json(injection_body, base_url):
        split = urlsplit(redirect_url)
        path = (split.path or "").rstrip("/")
        if not path:
            continue
        query = split.query or ""
        parts = [p for p in path.split("/") if p]
        if not parts:
            continue
        last = parts[-1].lower()
        read_suffixes = {s.lstrip("/") for s in _READ_PATH_SUFFIXES}
        mutation_suffixes = {s.lstrip("/") for s in _MUTATION_PATH_SUFFIXES}
        if last in read_suffixes or last in mutation_suffixes:
            continue
        collection = parts[-1]
        for url in _infer_read_urls_for_collection(base_url, collection, query=query):
            add(url)

    return found


def _infer_api_read_urls(surface: Any, base_url: str) -> list[str]:
    """Write/comment API surface에서 대응 read API URL을 추론."""
    found: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        normalized = _normalize_absolute(base_url, raw)
        if normalized and normalized not in seen:
            seen.add(normalized)
            found.append(normalized)

    for raw in (
        str(getattr(surface, "url", "") or ""),
        str(getattr(surface, "source_url", "") or ""),
    ):
        if not raw:
            continue
        view_tpl = _view_template_from_mutation_url(raw)
        if view_tpl:
            add(view_tpl)
        list_tpl = _list_template_from_mutation_url(raw)
        if list_tpl:
            add(list_tpl)
        api_variant = _client_route_to_api_url(raw, base_url)
        if api_variant:
            add(api_variant)

    return found


def _detail_url_with_id(template_url: str, resource_id: str) -> str:
    split = urlsplit(template_url)
    params = dict(parse_qsl(split.query, keep_blank_values=True))
    params["id"] = str(resource_id)
    query = urlencode(params)
    return urlunsplit((split.scheme, split.netloc, split.path, query, ""))


def extract_json_resource_detail_urls(
    body: str,
    base_url: str,
    *,
    surface_url: str = "",
    extra_view_templates: list[str] | None = None,
    max_items: int = 5,
) -> list[str]:
    """
    JSON 목록/단건 응답에서 id를 찾아 view URL 후보 생성.
    """
    text = (body or "").strip()
    if not text or text[0] not in "{[":
        return []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []

    templates: list[str] = []
    for raw in (surface_url, base_url):
        tpl = _view_template_from_mutation_url(raw)
        if tpl and tpl not in templates:
            templates.append(tpl)
    if not templates:
        split = urlsplit(surface_url or base_url)
        if "/api/" in (split.path or "").lower():
            path = split.path or ""
            for read_suffix in _READ_PATH_SUFFIXES:
                if read_suffix in path.lower():
                    templates.append(urlunsplit((split.scheme, split.netloc, path, "", "")))
                    break

    for raw_tpl in extra_view_templates or []:
        tpl = (raw_tpl or "").strip()
        if tpl and tpl not in templates:
            templates.append(tpl)

    if not templates:
        return []

    ids: list[str] = []

    def collect_ids(node: Any, depth: int = 0) -> None:
        if depth > 8 or len(ids) >= max_items * 3:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                key_lower = str(key).lower()
                if key_lower in _COLLECTION_ARRAY_KEYS and isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            raw_id = item.get("id")
                            if raw_id is not None:
                                id_str = str(raw_id).strip()
                                if id_str.isdigit():
                                    ids.append(id_str)
                if key_lower in _ID_FIELD_NAMES and value is not None:
                    id_str = str(value).strip()
                    if id_str.isdigit():
                        ids.append(id_str)
                else:
                    collect_ids(value, depth + 1)
        elif isinstance(node, list):
            for item in node:
                collect_ids(item, depth + 1)

    collect_ids(data)

    # newest/highest id first
    unique_ids: list[str] = []
    seen_ids: set[str] = set()
    for id_str in sorted({int(i) for i in ids if i.isdigit()}, reverse=True):
        key = str(id_str)
        if key in seen_ids:
            continue
        seen_ids.add(key)
        unique_ids.append(key)
        if len(unique_ids) >= max_items:
            break

    urls: list[str] = []
    seen_urls: set[str] = set()
    for template in templates:
        for resource_id in unique_ids:
            url = _detail_url_with_id(template, resource_id)
            url = _normalize_absolute(base_url, url)
            if url and url not in seen_urls:
                seen_urls.add(url)
                urls.append(url)
    return urls


def extract_redirect_urls_from_json(body: str, base_url: str) -> list[str]:
    """SPA mutating API의 redirect/location 필드에서 후속 GET 검증 URL 추출."""
    text = (body or "").strip()
    if not text or text[0] not in "{[":
        return []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []

    found: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        normalized = _normalize_absolute(base_url, raw)
        if normalized and normalized not in seen:
            seen.add(normalized)
            found.append(normalized)

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 6:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                key_lower = str(key).lower()
                if key_lower in _JSON_URL_KEYS and isinstance(value, str) and value.strip():
                    add(value)
                else:
                    walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node:
                walk(item, depth + 1)

    walk(data)
    expanded: list[str] = []
    for raw in found:
        expanded.append(raw)
        api_url = _client_route_to_api_url(raw, base_url)
        if api_url:
            expanded.append(api_url)
    return expanded


def _list_url_with_query(list_url: str, query: str) -> str:
    if not query:
        return list_url
    split = urlsplit(list_url)
    return urlunsplit((split.scheme, split.netloc, split.path, query, ""))


def infer_list_api_urls(surface: Any, base_url: str) -> list[str]:
    """write/add 뮤테이션 surface에서 대응 목록(list) API URL 추론."""
    return infer_list_poll_urls(surface, base_url, injection_body="")


def infer_list_poll_urls(
    surface: Any,
    base_url: str,
    injection_body: str = "",
) -> list[str]:
    """
    2차 검증 전 목록 API GET용 URL (mutation list + redirect list + 관련 컬렉션).
    redirect가 ``/board?type=general``이면 목록 API에도 동일 query를 붙인다.
    """
    ordered: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        normalized = _normalize_absolute(base_url, raw)
        if normalized and normalized not in seen:
            seen.add(normalized)
            ordered.append(normalized)

    redirect_queries: list[str] = []
    for redirect_url in extract_redirect_urls_from_json(injection_body, base_url):
        q = urlsplit(redirect_url).query
        if q and q not in redirect_queries:
            redirect_queries.append(q)

    for raw in (
        str(getattr(surface, "url", "") or ""),
        str(getattr(surface, "source_url", "") or ""),
    ):
        tpl = _list_template_from_mutation_url(raw)
        if tpl:
            add(_client_route_to_api_url(tpl, base_url) or tpl)
            for q in redirect_queries:
                api_list = _client_route_to_api_url(tpl, base_url) or tpl
                add(_list_url_with_query(api_list, q))

    for redirect_url in extract_redirect_urls_from_json(injection_body, base_url):
        split = urlsplit(redirect_url)
        path = split.path or ""
        if not path or "/view" in path.lower():
            continue
        api_list = _client_route_to_api_url(redirect_url, base_url)
        if api_list:
            add(api_list)

    for related in infer_related_read_api_urls(surface, base_url, injection_body):
        split = urlsplit(related)
        path_lower = (split.path or "").lower()
        if path_lower.endswith("/view"):
            continue
        add(related)

    return ordered


def _view_templates_for_surface(
    surface: Any,
    base_url: str,
    injection_body: str,
    surface_url: str,
) -> list[str]:
    templates: list[str] = []
    seen: set[str] = set()

    def add_tpl(raw: str) -> None:
        split = urlsplit((raw or "").strip())
        if not split.path or not split.path.lower().endswith("/view"):
            return
        tpl = urlunsplit((split.scheme, split.netloc, split.path, "", ""))
        if tpl and tpl not in seen:
            seen.add(tpl)
            templates.append(tpl)

    for raw in (surface_url,):
        tpl = _view_template_from_mutation_url(raw)
        if tpl:
            add_tpl(tpl)

    if surface is not None:
        for raw in infer_related_read_api_urls(surface, base_url, injection_body):
            add_tpl(raw)
        for raw in _infer_api_read_urls(surface, base_url):
            add_tpl(raw)

    return templates


def expand_detail_urls_from_list_bodies(
    list_bodies: list[tuple[str, str]],
    *,
    base_url: str,
    surface: Any = None,
    injection_body: str = "",
    surface_url: str = "",
    max_items: int = 5,
) -> list[str]:
    """목록 API 응답 JSON에서 최신 리소스 view URL을 추가 생성."""
    urls: list[str] = []
    seen: set[str] = set()
    extra_templates = _view_templates_for_surface(
        surface, base_url, injection_body, surface_url
    )
    for _list_url, body in list_bodies:
        for detail in extract_json_resource_detail_urls(
            body,
            base_url,
            surface_url=surface_url,
            extra_view_templates=extra_templates,
            max_items=max_items,
        ):
            if detail not in seen:
                seen.add(detail)
                urls.append(detail)
    return urls


def _urls_from_json_body(body: str, base_url: str) -> list[str]:
    text = (body or "").strip()
    if not text or text[0] not in "{[":
        return []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    found: set[str] = set()
    _urls_from_json(data, base_url, found)
    mapped: set[str] = set()
    for raw in list(found):
        mapped.add(raw)
        api_url = _client_route_to_api_url(raw, base_url)
        if api_url:
            mapped.add(api_url)
    return list(mapped)


def collect_verify_candidate_urls(
    *,
    base_url: str,
    surface: Any,
    injection_res: Any,
    max_detail_pages: int = 5,
    max_urls: int = 12,
) -> list[str]:
    """
    저장형 XSS 재검증에 GET할 URL 후보 목록 (중복 제거, 삽입 순서 유지).
    """
    ordered: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        normalized = _normalize_absolute(resolve_base, raw)
        if normalized:
            _append_unique(ordered, seen, normalized)

    resolve_base = (base_url or "").strip()
    if not resolve_base:
        resolve_base = str(getattr(injection_res, "url", "") or getattr(surface, "url", "") or "")

    final_url = str(getattr(injection_res, "url", "") or "")
    if final_url:
        add(final_url)
        if not resolve_base:
            resolve_base = final_url

    inj_headers = getattr(injection_res, "headers", None) or {}
    for header_url in _location_from_headers(inj_headers, resolve_base):
        add(header_url)

    injection_body = getattr(injection_res, "text", "") or ""
    surface_url = str(getattr(surface, "url", "") or "")
    expects_json = surface_expects_json_api(surface)

    if expects_json:
        for api_read in _infer_api_read_urls(surface, resolve_base):
            add(api_read)

        for related_read in infer_related_read_api_urls(surface, resolve_base, injection_body):
            add(related_read)

    if injection_body:
        for detail_url in extract_post_detail_urls(
            injection_body,
            resolve_base,
            max_posts=max_detail_pages,
        ):
            add(detail_url)
        if expects_json:
            for json_url in _urls_from_json_body(injection_body, resolve_base):
                add(json_url)
            for redirect_url in extract_redirect_urls_from_json(injection_body, resolve_base):
                add(redirect_url)
            for resource_url in extract_json_resource_detail_urls(
                injection_body,
                resolve_base,
                surface_url=surface_url,
                max_items=max_detail_pages,
            ):
                add(resource_url)

    if expects_json:
        for list_url in infer_list_poll_urls(surface, resolve_base, injection_body):
            add(list_url)

    source_url = getattr(surface, "source_url", None)
    for related in iter_related_crawl_urls(
        surface_url=surface_url,
        source_url=str(source_url) if source_url else None,
    ):
        add(related)
        if expects_json:
            api_related = _client_route_to_api_url(related, resolve_base)
            if api_related:
                add(api_related)

    if surface_url:
        add(surface_url)

    req_headers = getattr(surface, "headers", {}) or {}
    referer = req_headers.get("Referer") or req_headers.get("referer")
    if referer:
        add(str(referer))

    if base_url:
        add(base_url)
    elif resolve_base and resolve_base not in seen:
        add(resolve_base)

    if max_urls > 0 and len(ordered) > max_urls:
        return ordered[:max_urls]
    return ordered