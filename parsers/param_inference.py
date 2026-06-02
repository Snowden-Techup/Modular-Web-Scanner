"""보수적 쿼리 파라미터 추론 — 범용 스캐너용
크롤러가 엔드포인트 URL은 발견했지만 요청 파라미터가 누락된 경우(예: 쿼리 문자열 없이 캡처된 SPA XHR)에 사용됩니다. 
경로(Path) 기반의 휴리스틱으로만 추론을 수행하며, 이미 존재하는 파라미터는 절대 덮어쓰지 않습니다.
"""

from __future__ import annotations

from urllib.parse import urlparse

from parsers.http_method_inference import path_uses_query_params

# Path segment keyword -> likely query parameter names (ordered by preference).
COMMON_QUERY_PARAMS: dict[str, tuple[str, ...]] = {
    "search": ("q", "query", "keyword", "term", "s"),
    "find": ("q", "query", "keyword"),
    "lookup": ("q", "query"),
    "filter": ("filter", "category", "type", "tag"),
    "products": ("q", "query", "category"),
    "product": ("id", "productId", "sku"),
    "user": ("id", "userId", "uid"),
    "users": ("id", "userId"),
    "order": ("id", "orderId"),
    "orders": ("id", "orderId"),
    "review": ("id", "productId"),
    "reviews": ("id", "productId"),
    "board": ("type", "id", "post_id"),
    "post": ("id", "post_id"),
    "comment": ("id", "post_id"),
    "logs": ("file", "path", "name"),
    "log": ("file", "path", "name"),
    "view": ("id", "file"),
    "write": ("type", "post_type"),
    "edit": ("id",),
    "delete": ("id",),
    "file": ("file", "path", "name"),
    "download": ("file", "path"),
    "upload": ("file", "path"),
    "redirect": ("url", "to", "next", "target", "redirect"),
    "page": ("page", "p", "offset", "limit"),
    "list": ("page", "limit", "offset"),
    "books": ("category", "limit", "page"),
    "book": ("id", "book_id"),
    "cart": ("book_id", "id"),
    "wishlist": ("book_id", "id"),
    "profile": ("id",),
    "checkout": ("book_id", "price"),
}

# Empty seed matches typical HTML form defaults; fuzzer replaces with payloads.
_DEFAULT_PLACEHOLDER = ""


def _path_key(url: str) -> str:
    return (urlparse(url).path or "/").lower().rstrip("/") or "/"


def resolve_query_param_seed(
    url: str,
    *,
    observed_names: dict[str, set[str]] | None = None,
    observed_values: dict[str, dict[str, str]] | None = None,
    placeholder: str = _DEFAULT_PLACEHOLDER,
) -> dict[str, str]:
    """
    Build GET query parameter seeds for a URL.

    Priority: explicit query string > observed values (same crawl) >
    observed names only > path heuristics.
    """
    if not url:
        return {}

    parsed = urlparse(url)
    if parsed.query:
        return {}
    if not path_uses_query_params(url):
        return {}

    path_key = _path_key(url)

    if observed_values:
        for obs_path, samples in observed_values.items():
            if not samples:
                continue
            obs_norm = (obs_path or "/").lower().rstrip("/") or "/"
            if path_key == obs_norm or path_key.endswith(obs_norm) or obs_norm.endswith(path_key):
                return {str(k): str(v) for k, v in samples.items()}

    if observed_names:
        for obs_path, names in observed_names.items():
            if not names:
                continue
            obs_norm = (obs_path or "/").lower().rstrip("/") or "/"
            if path_key == obs_norm or path_key.endswith(obs_norm) or obs_norm.endswith(path_key):
                return {name: placeholder for name in sorted(names)}

    return infer_query_params(url, placeholder=placeholder)


def infer_query_params(
    url: str,
    *,
    observed: dict[str, set[str]] | None = None,
    placeholder: str = _DEFAULT_PLACEHOLDER,
) -> dict[str, str]:
    """
    Infer GET query parameter names from URL path patterns.

    ``observed`` maps normalized path keys to parameter names seen on similar
    endpoints during the same crawl session (stronger signal than heuristics).
    """
    if not url:
        return {}

    parsed = urlparse(url)
    if parsed.query:
        return {}
    if not path_uses_query_params(url):
        return {}

    path_key = _path_key(url)

    if observed:
        for obs_path, names in observed.items():
            if not names:
                continue
            obs_norm = (obs_path or "/").lower().rstrip("/") or "/"
            if path_key == obs_norm or path_key.endswith(obs_norm) or obs_norm.endswith(path_key):
                return {name: placeholder for name in sorted(names)}

    matched: list[str] = []
    segments = [seg for seg in path_key.split("/") if seg]
    segment_set = set(segments)
    for keyword, param_names in COMMON_QUERY_PARAMS.items():
        if keyword in segment_set:
            matched.extend(param_names)

    if not matched:
        return {}

    seen: set[str] = set()
    unique: list[str] = []
    for name in matched:
        if name not in seen:
            seen.add(name)
            unique.append(name)

    capped = unique[:2]
    return {name: placeholder for name in capped}


def merge_inferred_query_params(
    url: str,
    parameters: dict[str, str],
    *,
    observed: dict[str, set[str]] | None = None,
    observed_values: dict[str, dict[str, str]] | None = None,
) -> dict[str, str]:
    """Return parameters unchanged if non-empty; otherwise apply inference."""
    if parameters:
        return dict(parameters)
    inferred = resolve_query_param_seed(
        url,
        observed_names=observed,
        observed_values=observed_values,
    )
    return inferred if inferred else {}
