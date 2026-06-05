"""Core SPA capture helpers (normalization, interceptors, synthesis)."""

from __future__ import annotations

import hashlib
import html
import json
import logging
import re
from urllib.parse import parse_qsl, urlencode, urlparse

from crawler.spa.browser import ROUTE_EXTRACT_JS
from parsers.param_inference import resolve_query_param_seed

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants and shared patterns
# ---------------------------------------------------------------------------

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_CAPTURE_SOURCES = frozenset({"capture", "auth-login-json", "auth-login-form", "seed", "observed-body"})

MAX_PAYLOAD_SIZE = 512 * 1024
MAX_SYNTHESIZED_LINKS = 200
MAX_SYNTHESIZED_APIS = 200
MAX_GRAPHQL_SCHEMAS = 150
MAX_URL_CACHE_SIZE = 10000
MAX_ID_SAMPLES_PER_PATTERN = 3

UUID_REGEX = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
OBJECT_ID_REGEX = re.compile(r"(?<=/)[0-9a-fA-F]{24}(?=/|$)")
NUM_ID_REGEX = re.compile(r"(?<=/)\d+(?=/|$)")
LONG_TOKEN_REGEX = re.compile(r"(?<=/)[A-Za-z0-9_-]{32,}(?=/|$)")
GQL_OP_RE = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)

INTROSPECTION_QUERY = """
    query {
        __schema {
            queryType { name }
            mutationType { name }
            types {
                name
                kind
                fields {
                    name
                    args {
                        name
                        type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
                    }
                }
            }
        }
    }
    """

_HIGH_PRIORITY_ROUTE_PATTERNS = re.compile(
    r"/(?:admin|administrator|payment|checkout|account|profile|"
    r"user|users|api|graphql|upload|settings?|config|dashboard|"
    r"order|cart|wallet|billing|invoice)(?:/|$)",
    re.IGNORECASE,
)
_LOW_PRIORITY_ROUTE_PATTERNS = re.compile(
    r"/(?:about|contact|help|faq|terms|privacy|policy|legal|"
    r"static|public|assets|i18n)(?:/|$)",
    re.IGNORECASE,
)
_MULTIPART_NAME_RE = re.compile(
    r'content-disposition:\s*form-data;\s*name="([^"]+)"',
    re.IGNORECASE,
)
_MULTIPART_FILENAME_RE = re.compile(r"filename\s*=", re.IGNORECASE)

# ---------------------------------------------------------------------------
# URL normalization and API key helpers
# ---------------------------------------------------------------------------


def generate_api_hash(method: str, url: str) -> str:
    return hashlib.md5(f"{method}:{url}".encode()).hexdigest()


def normalize_url(engine, url: str) -> str:
    cache = engine._url_cache
    if url in cache:
        return cache[url]
    parsed = urlparse(url)
    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    path = UUID_REGEX.sub("{id}", path)
    path = OBJECT_ID_REGEX.sub("{id}", path)
    path = NUM_ID_REGEX.sub("{id}", path)
    path = LONG_TOKEN_REGEX.sub("{token}", path)
    query_keys = sorted(k for k, _ in parse_qsl(parsed.query))
    query_str = "?" + "&".join(f"{k}={{val}}" for k in query_keys) if query_keys else ""
    normalized = f"{parsed.scheme}://{parsed.netloc}{path}{query_str}"
    if len(cache) > MAX_URL_CACHE_SIZE:
        cache.clear()
    cache[url] = normalized
    return normalized


def normalize_path_like(value: str) -> str:
    normalized = value or "/"
    if len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized.rstrip("/")
    normalized = UUID_REGEX.sub("{id}", normalized)
    normalized = OBJECT_ID_REGEX.sub("{id}", normalized)
    normalized = NUM_ID_REGEX.sub("{id}", normalized)
    normalized = LONG_TOKEN_REGEX.sub("{token}", normalized)
    return normalized


def normalize_fragment_route(fragment: str) -> str:
    frag = str(fragment or "").strip()
    if not frag or not (frag.startswith("/") or frag.startswith("!/")):
        return ""
    bang = frag.startswith("!/")
    frag_body = frag[1:] if bang else frag
    parsed = urlparse(frag_body)
    path = normalize_path_like(parsed.path or "/")
    query_keys = sorted(k for k, _ in parse_qsl(parsed.query, keep_blank_values=True))
    query = "?" + "&".join(query_keys) if query_keys else ""
    prefix = "!" if bang else ""
    return f"{prefix}{path}{query}"


def normalize_route_context(url: str) -> str:
    parsed = urlparse(url)
    path = normalize_path_like(parsed.path or "/")
    query_keys = sorted(k for k, _ in parse_qsl(parsed.query, keep_blank_values=True))
    query = "?" + "&".join(query_keys) if query_keys else ""
    fragment = normalize_fragment_route(parsed.fragment)
    if fragment:
        return f"{path}{query}#{fragment}"
    return f"{path}{query}"


def extract_hash_route_context(request) -> str:
    candidates: list[str] = []
    try:
        headers = request.headers or {}
        for header_name in ("referer", "referrer"):
            value = headers.get(header_name)
            if value:
                candidates.append(str(value))
    except Exception:
        pass
    try:
        frame = getattr(request, "frame", None)
        frame_url = getattr(frame, "url", None)
        if frame_url:
            candidates.append(str(frame_url))
    except Exception:
        pass
    for candidate in candidates:
        normalized = normalize_route_context(candidate)
        if "#" in normalized:
            return normalized
    return ""


def extract_payload_shape(post_data: str | None, content_type: str | None) -> str:
    if not post_data:
        return ""
    body = str(post_data)
    ct = str(content_type or "").lower()
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        data = None
    if isinstance(data, dict):
        if isinstance(data.get("query"), str):
            query = str(data.get("query") or "")
            op_match = GQL_OP_RE.search(query)
            op_type = op_match.group(1).lower() if op_match else "query"
            op_name = str(data.get("operationName") or (op_match.group(2) if op_match else "unknown"))
            variables = data.get("variables")
            variable_keys = ",".join(sorted(str(k) for k in variables.keys())) if isinstance(variables, dict) else ""
            return f"graphql:{op_type}:{op_name}:{variable_keys}"
        return "json:" + ",".join(sorted(str(k) for k in data.keys()))
    if isinstance(data, list):
        if data and isinstance(data[0], dict):
            keys = sorted(str(k) for k in data[0].keys())
            return "json-list:" + ",".join(keys)
        return f"json-list:{len(data)}"
    form_keys = sorted({str(k) for k, _ in parse_qsl(body, keep_blank_values=True)})
    if form_keys:
        return "form:" + ",".join(form_keys)
    html_keys = sorted(set(re.findall(r'name="([^"]+)"', body)))
    if html_keys:
        return "html-form:" + ",".join(html_keys)
    gql_match = GQL_OP_RE.search(body)
    if gql_match:
        return f"graphql-raw:{gql_match.group(1).lower()}:{gql_match.group(2)}"
    if "application/json" in ct:
        return "json-raw"
    if "application/x-www-form-urlencoded" in ct:
        return "form-raw"
    return ""


def build_api_key_parts(
    method: str,
    normalized_url: str,
    *,
    content_type_base: str = "",
    payload_shape: str = "",
    route_context: str = "",
) -> list[str]:
    parts = [str(method).upper(), normalized_url]
    if content_type_base:
        parts.append(content_type_base)
    if payload_shape:
        parts.append(payload_shape)
    if route_context:
        parts.append(f"route:{route_context}")
    return parts


def canonicalize_sample_path(path: str) -> str:
    sample_path = path or "/"
    if len(sample_path) > 1 and sample_path.endswith("/"):
        sample_path = sample_path.rstrip("/")
    return sample_path


def extract_preservable_path_sample(original_url: str, normalized_url: str) -> str:
    parsed_orig = urlparse(original_url)
    parsed_norm = urlparse(normalized_url)
    original_path = canonicalize_sample_path(parsed_orig.path)
    normalized_path = canonicalize_sample_path(parsed_norm.path)
    if original_path == normalized_path:
        return ""
    if "{id}" not in normalized_path and "{token}" not in normalized_path:
        return ""
    return original_path


def reserve_path_sample_slot(engine, pattern_key: str, sample_path: str) -> int | None:
    sample_slots = getattr(engine, "id_sample_slots", None)
    if sample_slots is None or not sample_path:
        return None
    bucket = sample_slots.setdefault(pattern_key, {})
    existing_slot = bucket.get(sample_path)
    if existing_slot is not None:
        return existing_slot
    if len(bucket) >= MAX_ID_SAMPLES_PER_PATTERN:
        return None
    slot = len(bucket) + 1
    bucket[sample_path] = slot
    metrics = getattr(engine, "metrics", None)
    if isinstance(metrics, dict) and "id_samples_preserved" in metrics:
        metrics["id_samples_preserved"] += 1
    return slot


def build_api_candidate_key(
    engine,
    method: str,
    url: str,
    *,
    req_content_type: str = "",
    post_data: str | None = None,
    route_context: str = "",
    preserve_id_samples: bool = True,
) -> str:
    normalized_url = normalize_url(engine, url)
    content_type_base = str(req_content_type or "").lower().split(";", 1)[0].strip()
    payload_shape = extract_payload_shape(post_data, content_type_base)
    base_key = " | ".join(
        build_api_key_parts(
            method,
            normalized_url,
            content_type_base=content_type_base,
            payload_shape=payload_shape,
            route_context=route_context,
        )
    )
    if not preserve_id_samples:
        return base_key
    sample_path = extract_preservable_path_sample(url, normalized_url)
    if not sample_path:
        return base_key
    pattern_key = " | ".join(
        build_api_key_parts(
            method,
            normalized_url,
            content_type_base=content_type_base,
            payload_shape=payload_shape,
            route_context="",
        )
    )
    sample_slot = reserve_path_sample_slot(engine, pattern_key, sample_path)
    if sample_slot is None:
        return base_key
    return f"{base_key} | path_sample:{sample_slot}"


def build_api_cluster_key(engine, request) -> str:
    return build_api_candidate_key(
        engine,
        request.method,
        request.url,
        req_content_type=request.headers.get("content-type", ""),
        post_data=request.post_data,
        route_context=extract_hash_route_context(request),
    )


def build_api_base_key(engine, method: str, url: str, *, req_content_type: str = "", post_data: str | None = None) -> str:
    return build_api_candidate_key(
        engine,
        method,
        url,
        req_content_type=req_content_type,
        post_data=post_data,
        route_context="",
        preserve_id_samples=False,
    )


def path_key_from_url(url: str) -> str:
    return (urlparse(url).path or "/").rstrip("/").lower() or "/"


def store_observed_sample(bucket: dict[str, str], key: str, value: str) -> None:
    key_str = str(key).strip()
    if not key_str:
        return
    val_str = str(value)
    if key_str not in bucket:
        bucket[key_str] = val_str
        return
    if not bucket[key_str] and val_str:
        bucket[key_str] = val_str


def extract_multipart_boundary(body: str, content_type: str) -> str:
    match = re.search(r"boundary=([^;\s]+)", str(content_type or ""), re.IGNORECASE)
    if match:
        return match.group(1).strip().strip('"').strip("'")
    stripped = body.lstrip()
    if stripped.startswith("--"):
        first_line = stripped.split("\n", 1)[0].strip()
        return first_line[2:].strip()
    return ""


def parse_multipart_file_field_names(body: str, content_type: str) -> set[str]:
    """Multipart parts that include a filename= attribute (file uploads)."""
    if not body:
        return set()
    text = str(body)
    ct = str(content_type or "").lower()
    if "multipart/form-data" not in ct and not text.lstrip().startswith("--"):
        return set()
    boundary = extract_multipart_boundary(text, content_type)
    if not boundary:
        return set()
    names: set[str] = set()
    delimiter = f"--{boundary}"
    for part in text.split(delimiter):
        chunk = part.strip()
        if not chunk or chunk == "--":
            continue
        header_block = chunk.split("\r\n\r\n", 1)[0] if "\r\n\r\n" in chunk else chunk.split("\n\n", 1)[0]
        if not _MULTIPART_FILENAME_RE.search(header_block):
            continue
        name_match = _MULTIPART_NAME_RE.search(header_block)
        if name_match:
            names.add(str(name_match.group(1)).strip())
    return names


def parse_multipart_fields(body: str, content_type: str) -> dict[str, str]:
    if not body:
        return {}
    text = str(body)
    ct = str(content_type or "").lower()
    if "multipart/form-data" not in ct and not text.lstrip().startswith("--"):
        return {}
    boundary = extract_multipart_boundary(text, content_type)
    if not boundary:
        return {}
    fields: dict[str, str] = {}
    delimiter = f"--{boundary}"
    for part in text.split(delimiter):
        chunk = part.strip()
        if not chunk or chunk == "--":
            continue
        name_match = _MULTIPART_NAME_RE.search(chunk)
        if not name_match:
            continue
        name = str(name_match.group(1)).strip()
        if not name:
            continue
        if "\r\n\r\n" in chunk:
            _, raw_value = chunk.split("\r\n\r\n", 1)
        elif "\n\n" in chunk:
            _, raw_value = chunk.split("\n\n", 1)
        else:
            continue
        value = raw_value.strip().rstrip("-").strip()
        store_observed_sample(fields, name, value)
    return fields


def parse_payload_fields(post_data: str, content_type: str) -> dict[str, str]:
    if not post_data:
        return {}
    body = str(post_data)
    ct = str(content_type or "").lower()
    if "multipart/form-data" in ct or body.lstrip().startswith("--"):
        fields = parse_multipart_fields(body, content_type)
        if fields:
            return fields
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        data = None
    if isinstance(data, dict):
        return {str(k): str(v) for k, v in data.items() if str(k).strip()}
    if "application/x-www-form-urlencoded" in ct or ("=" in body and "content-disposition" not in body.lower() and not body.lstrip().startswith("--")):
        fields: dict[str, str] = {}
        for key, val in parse_qsl(body, keep_blank_values=True):
            if str(key).strip():
                fields[str(key)] = str(val)
        return fields
    return {}


def serialize_body_fields(fields: dict[str, str], content_type: str) -> tuple[str, str]:
    ct = str(content_type or "").lower().split(";", 1)[0].strip()
    clean = {str(k): str(v) for k, v in fields.items() if str(k).strip()}
    if ct == "multipart/form-data":
        # Preserve observed field names; synthesized forms carry values separately.
        return "", "multipart/form-data"
    if ct == "application/x-www-form-urlencoded":
        return urlencode(clean, doseq=True), "application/x-www-form-urlencoded"
    return json.dumps(clean, ensure_ascii=False), "application/json"

# ---------------------------------------------------------------------------
# Observations and scope checks
# ---------------------------------------------------------------------------


def register_observed_query_keys(engine, url: str) -> None:
    parsed = urlparse(url)
    if not parsed.query:
        return
    path_key = path_key_from_url(url)
    names_map = getattr(engine, "observed_query_params", None)
    if names_map is None:
        engine.observed_query_params = {}
        names_map = engine.observed_query_params
    names = names_map.setdefault(path_key, set())
    samples_map = getattr(engine, "observed_query_samples", None)
    if samples_map is None:
        engine.observed_query_samples = {}
        samples_map = engine.observed_query_samples
    samples = samples_map.setdefault(path_key, {})
    for key, val in parse_qsl(parsed.query, keep_blank_values=True):
        key_str = str(key).strip()
        if not key_str:
            continue
        names.add(key_str)
        store_observed_sample(samples, key_str, val)


def register_observed_body_field_hints(
    engine,
    path_key: str,
    field_names: set[str] | frozenset[str] | list[str],
) -> None:
    """XHR/DOM/JS 정적 분석에서 확인된 필드명을 path_key 샘플에 병합 (값은 빈 placeholder)."""
    if not path_key or not field_names:
        return
    samples_map = getattr(engine, "observed_body_samples", None)
    if samples_map is None:
        engine.observed_body_samples = {}
        samples_map = engine.observed_body_samples
    bucket = samples_map.setdefault(path_key, {})
    from parsers.body_field_inference import is_plausible_field_name

    for raw_name in field_names:
        key_str = str(raw_name).strip()
        if not key_str or not is_plausible_field_name(key_str):
            continue
        store_observed_sample(bucket, key_str, str(bucket.get(key_str) or ""))


def _spa_path_keys_related(api_path_key: str, sample_key: str) -> bool:
    from crawler.spa.path_family import spa_path_keys_related

    return spa_path_keys_related(api_path_key, sample_key)


def register_observed_body_keys(engine, url: str, post_data: str | None, content_type: str) -> None:
    fields = parse_payload_fields(post_data or "", content_type)
    file_names = parse_multipart_file_field_names(post_data or "", content_type)
    if not fields and not file_names:
        return
    path_key = path_key_from_url(url)
    names_map = getattr(engine, "observed_body_params", None)
    if names_map is None:
        engine.observed_body_params = {}
        names_map = engine.observed_body_params
    names = names_map.setdefault(path_key, set())
    samples_map = getattr(engine, "observed_body_samples", None)
    if samples_map is None:
        engine.observed_body_samples = {}
        samples_map = engine.observed_body_samples
    samples = samples_map.setdefault(path_key, {})
    for key, val in fields.items():
        names.add(key)
        store_observed_sample(samples, key, val)
    if file_names:
        file_map = getattr(engine, "observed_body_file_fields", None)
        if file_map is None:
            engine.observed_body_file_fields = {}
            file_map = engine.observed_body_file_fields
        file_bucket = file_map.setdefault(path_key, set())
        file_bucket.update(file_names)
        names.update(file_names)
        for key in file_names:
            if key not in samples:
                samples[key] = ""
    if content_type:
        ct_map = getattr(engine, "observed_body_content_types", None)
        if ct_map is None:
            engine.observed_body_content_types = {}
            ct_map = engine.observed_body_content_types
        base_ct = str(content_type).split(";", 1)[0].strip().lower()
        if base_ct:
            ct_map[path_key] = base_ct


def is_in_scope(engine, url: str) -> bool:
    try:
        return urlparse(url).hostname == engine.target_domain
    except Exception as exc:
        logger.debug("[SPA Crawler] Scope check failed for %s: %s", url, exc)
        return False


def should_collect_url(engine, url: str) -> bool:
    if not url or not is_in_scope(engine, url):
        return False
    if engine.url_filter is not None:
        return engine.url_filter.is_crawlable(url)
    return True


def api_source_rank(source: str) -> int:
    src = str(source or "").lower()
    if src in _CAPTURE_SOURCES:
        return 2
    if src == "js-static":
        return 0
    return 1


def api_has_live_signal(engine, api: dict) -> bool:
    parsed = urlparse(api.get("url") or "")
    if parsed.query or api.get("post_data") or api_source_rank(str(api.get("source") or "")) >= 2:
        return True
    path_key = path_key_from_url(api.get("url") or "")
    return bool((getattr(engine, "observed_query_samples", None) or {}).get(path_key) or (getattr(engine, "observed_body_samples", None) or {}).get(path_key))


def drop_get_stubs_for_path(engine, path_key: str) -> None:
    for existing_hash, entry in list(engine.api_endpoints.items()):
        if path_key_from_url(entry.get("url") or "") != path_key:
            continue
        if str(entry.get("method") or "GET").upper() != "GET":
            continue
        if urlparse(entry.get("url") or "").query:
            continue
        source = str(entry.get("source") or "")
        if source != "js-static" and api_has_live_signal(engine, entry):
            continue
        del engine.api_endpoints[existing_hash]


def _merge_api_file_fields(entry: dict, post_data: str | None, req_content_type: str) -> None:
    discovered = parse_multipart_file_field_names(post_data or "", req_content_type or "")
    if not discovered:
        return
    merged = set(entry.get("file_fields") or ())
    merged.update(discovered)
    entry["file_fields"] = sorted(merged)
    if not entry.get("req_content_type") or "json" in str(entry.get("req_content_type")).lower():
        entry["req_content_type"] = req_content_type or "multipart/form-data"


def record_api_candidate(
    engine,
    *,
    method: str,
    url: str,
    post_data: str | None = None,
    req_content_type: str = "",
    status: int | None = None,
    content_type: str | None = None,
    route_context: str = "",
    source_url: str = "",
    source: str = "capture",
) -> tuple[str | None, bool]:
    if not should_collect_url(engine, url):
        return None, False
    cluster_key = build_api_candidate_key(engine, method, url, req_content_type=req_content_type, post_data=post_data, route_context=route_context)
    base_cluster_key = build_api_base_key(engine, method, url, req_content_type=req_content_type, post_data=post_data)
    api_hash = generate_api_hash(str(method).upper(), cluster_key)
    existing = engine.api_endpoints.get(api_hash)
    if existing is not None:
        if post_data and not existing.get("post_data"):
            existing["post_data"] = post_data
            if str(method).upper() in _MUTATING_METHODS:
                drop_get_stubs_for_path(engine, path_key_from_url(url))
        elif post_data and existing.get("post_data"):
            old_fields = parse_payload_fields(existing.get("post_data") or "", existing.get("req_content_type") or "")
            new_fields = parse_payload_fields(post_data, req_content_type)
            if len(new_fields) > len(old_fields):
                existing["post_data"] = post_data
                existing["req_content_type"] = req_content_type or existing.get("req_content_type")
        if req_content_type and not existing.get("req_content_type"):
            existing["req_content_type"] = req_content_type
        if status is not None:
            existing["status"] = status
        if content_type and not existing.get("content_type"):
            existing["content_type"] = content_type
        if source_url and not existing.get("source_url"):
            existing["source_url"] = source_url
        if "depth" not in existing:
            existing["depth"] = int(getattr(engine, "current_route_depth", 0) or 0)
        if source and existing.get("source") == "js-static":
            existing["source"] = source
        _merge_api_file_fields(existing, post_data, req_content_type)
        return api_hash, False
    if source == "js-static":
        # Snapshot items to avoid size-change errors while network callbacks update endpoints.
        for existing_hash, entry in list(engine.api_endpoints.items()):
            if entry.get("base_cluster_key") == base_cluster_key:
                return existing_hash, False
    else:
        for existing_hash, entry in list(engine.api_endpoints.items()):
            if entry.get("base_cluster_key") == base_cluster_key and entry.get("source") == "js-static":
                del engine.api_endpoints[existing_hash]
    engine.api_endpoints[api_hash] = {
        "url": url,
        "method": str(method).upper(),
        "post_data": post_data,
        "req_content_type": req_content_type or "",
        "cluster_key": cluster_key,
        "base_cluster_key": base_cluster_key,
        "route_context": route_context,
        "source_url": source_url,
        "source": source,
        "status": status,
        "content_type": content_type,
        "depth": int(getattr(engine, "current_route_depth", 0) or 0),
        "file_fields": [],
    }
    _merge_api_file_fields(engine.api_endpoints[api_hash], post_data, req_content_type)
    if str(method).upper() in _MUTATING_METHODS and post_data:
        drop_get_stubs_for_path(engine, path_key_from_url(url))
    return api_hash, True


def record_graphql_capture(engine, url: str, post_data: str | None) -> None:
    from crawler.spa.capture_graphql import record_graphql_capture as _record_graphql_capture

    _record_graphql_capture(engine, url, post_data)

# ---------------------------------------------------------------------------
# Network interception
# ---------------------------------------------------------------------------


def compact_response_headers(headers: dict[str, str] | None) -> dict[str, str]:
    if not headers:
        return {}
    keep = ("server", "x-powered-by", "content-type", "cache-control", "etag", "set-cookie")
    out: dict[str, str] = {}
    for key, value in (headers or {}).items():
        lowered = str(key).lower()
        if lowered in keep:
            out[lowered] = str(value)
    return out


def server_info_from_headers(headers: dict[str, str]) -> dict[str, str]:
    if not headers:
        return {}
    server = headers.get("server") or headers.get("x-powered-by")
    return {"web_server": str(server)} if server else {}


def intercept_request(engine, request) -> None:
    if request.resource_type not in ("xhr", "fetch") or not should_collect_url(engine, request.url):
        return
    register_observed_query_keys(engine, request.url)
    post_data = request.post_data
    register_observed_body_keys(engine, request.url, post_data, request.headers.get("content-type", ""))
    if "graphql" in request.url.lower():
        record_graphql_capture(engine, request.url, post_data)
    if post_data and len(post_data) > MAX_PAYLOAD_SIZE:
        engine.metrics["payload_dropped"] += 1
        return
    route_context = extract_hash_route_context(request) or normalize_route_context(str(getattr(engine, "current_route_url", "") or ""))
    api_hash, created = record_api_candidate(
        engine,
        method=request.method,
        url=request.url,
        post_data=post_data,
        req_content_type=request.headers.get("content-type", "application/json"),
        route_context=route_context,
        source_url=str(getattr(engine, "current_route_url", "") or ""),
        source="capture",
    )
    if api_hash is not None and not created:
        engine.metrics["apis_clustered"] += 1


def intercept_response(engine, response) -> None:
    request = response.request
    if request.resource_type not in ("xhr", "fetch"):
        return
    route_context = extract_hash_route_context(request) or normalize_route_context(str(getattr(engine, "current_route_url", "") or ""))
    api_hash = generate_api_hash(
        request.method,
        build_api_candidate_key(
            engine,
            request.method,
            request.url,
            req_content_type=request.headers.get("content-type", ""),
            post_data=request.post_data,
            route_context=route_context,
        ),
    )
    if api_hash not in engine.api_endpoints:
        return
    entry = engine.api_endpoints[api_hash]
    entry["status"] = response.status
    response_headers = {str(k).lower(): str(v) for k, v in (response.headers or {}).items()}
    if not entry.get("content_type"):
        entry["content_type"] = response_headers.get("content-type", "unknown").lower()
    if not entry.get("response_headers"):
        compact = compact_response_headers(response_headers)
        if compact:
            entry["response_headers"] = compact
    if not entry.get("server_info"):
        entry["server_info"] = server_info_from_headers(response_headers)
    if not entry.get("response_headers"):
        fallback_ct = str(entry.get("content_type") or entry.get("req_content_type") or "").strip()
        if fallback_ct:
            entry["response_headers"] = {"content-type": fallback_ct}


def route_priority(url: str) -> int:
    if not url:
        return 0
    if _HIGH_PRIORITY_ROUTE_PATTERNS.search(url):
        return 1
    if _LOW_PRIORITY_ROUTE_PATTERNS.search(url):
        return -1
    return 0

# ---------------------------------------------------------------------------
# Route collection and HTML synthesis
# ---------------------------------------------------------------------------


def enqueue_routes(engine, routes, routes_to_visit, queued_routes, visited_routes, *, route_depths: dict[str, int] | None = None, parent_depth: int = 0, max_queue=200):
    for route in routes:
        if route in visited_routes or route in queued_routes:
            continue
        if not should_collect_url(engine, route):
            continue
        if engine.url_filter is not None and engine.url_filter.is_visited(route):
            visited_routes.add(route)
            continue
        if len(queued_routes) >= max_queue:
            break
        routes_to_visit.append(route)
        queued_routes.add(route)
        if route_depths is not None:
            route_depths.setdefault(route, max(0, int(parent_depth)) + 1)
    routes_to_visit.sort(key=lambda u: -route_priority(u))


async def collect_routes_from_page(page) -> list[str]:
    try:
        return await page.evaluate(ROUTE_EXTRACT_JS)
    except Exception as e:
        logger.debug("[SPA Crawler] Route extraction failed: %s", e)
        return []


async def extract_dom_links(engine, page) -> None:
    try:
        for u in await page.evaluate(ROUTE_EXTRACT_JS):
            if not u.startswith("http"):
                continue
            if should_collect_url(engine, u):
                engine.found_urls.add(u)
            else:
                engine.metrics["oos_blocked"] += 1
    except Exception as e:
        logger.warning("[SPA Crawler] DOM extraction failed: %s", e)


def build_synthesized_html(engine, final_html: str, graphql_html: str) -> str:
    from crawler.spa.capture_enrichment import (
        enrich_api_endpoints_from_observations,
        enrich_source_urls,
        fallback_content_type_for_api,
        fallback_server_info_for_api,
        infer_companion_action_endpoints,
        normalize_mutating_path_endpoints,
        prioritize_api_endpoints,
    )

    source_enriched = enrich_source_urls(engine)
    if source_enriched:
        logger.info("[SPA Crawler] Enriched source_url for %s endpoint(s)", source_enriched)
    companion_added = infer_companion_action_endpoints(engine)
    if companion_added:
        logger.info("[SPA Crawler] Inferred %s companion action endpoint(s)", companion_added)
    normalized = normalize_mutating_path_endpoints(engine)
    if normalized:
        logger.info("[SPA Crawler] Normalized %s path(s) to POST from URL action segments", normalized)
    promoted = enrich_api_endpoints_from_observations(engine)
    if promoted:
        logger.info("[SPA Crawler] Promoted %s POST endpoint(s) from observed XHR bodies", promoted)

    synthesized = "\n\n<div style='display:none;'>\n" + graphql_html
    link_count = 0
    for url in engine.found_urls:
        if link_count >= MAX_SYNTHESIZED_LINKS:
            break
        synthesized += f'<a href="{html.escape(url, quote=True)}">Synthesized Link</a>\n'
        link_count += 1
        engine.metrics["links_extracted"] += 1

    api_count = 0
    observed_names = getattr(engine, "observed_query_params", None)
    observed_values = getattr(engine, "observed_query_samples", None)
    observed_body = getattr(engine, "observed_body_samples", None)

    for api in prioritize_api_endpoints(engine):
        if api_count >= MAX_SYNTHESIZED_APIS:
            break
        method = api["method"].upper()
        action = html.escape(api["url"], quote=True)
        fallback_ct = fallback_content_type_for_api(api)
        req_ct_raw = str(api.get("req_content_type") or "").strip()
        ct_base = (
            req_ct_raw.split(";", 1)[0].strip().lower()
            if req_ct_raw
            else str(fallback_ct or "application/json").lower()
        )
        path_key = path_key_from_url(api["url"])
        file_fields: set[str] = set(api.get("file_fields") or ())
        observed_file_map = getattr(engine, "observed_body_file_fields", None) or {}
        file_fields.update(observed_file_map.get(path_key) or ())
        if file_fields:
            ct_base = "multipart/form-data"
        ct = html.escape(ct_base or "application/json", quote=True)
        form_enctype_attr = (
            ' enctype="multipart/form-data"' if ct_base == "multipart/form-data" else ""
        )
        inputs = ""
        parsed = urlparse(api["url"])
        inferred_flag = False
        if method == "GET":
            query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if not query_params:
                query_params = resolve_query_param_seed(api["url"], observed_names=observed_names, observed_values=observed_values)
                inferred_flag = bool(query_params) and not ((observed_values or {}).get(path_key))
            for key, val in query_params.items():
                inputs += f'  <input name="{html.escape(str(key), quote=True)}" value="{html.escape(str(val), quote=True)}">\n'
        post_data = api.get("post_data")
        body_fields: dict[str, str] = {}
        if method in _MUTATING_METHODS:
            if post_data:
                body_fields = parse_payload_fields(post_data, api.get("req_content_type") or "")
            if not body_fields:
                body_fields = dict((observed_body or {}).get(path_key) or {})
            from crawler.spa.capture_enrichment import resolve_mutating_body_fields

            body_fields = resolve_mutating_body_fields(
                engine,
                path_key,
                local_fields=body_fields,
                source_url=str(api.get("source_url") or ""),
                url=str(api.get("url") or ""),
            )
        rendered_names: set[str] = set()
        for key, val in body_fields.items():
            rendered_names.add(str(key))
            if str(key) in file_fields:
                inputs += f'  <input type="file" name="{html.escape(str(key), quote=True)}">\n'
            else:
                inputs += (
                    f'  <input name="{html.escape(str(key), quote=True)}" '
                    f'value="{html.escape(str(val), quote=True)}">\n'
                )
        for key in sorted(file_fields):
            if key in rendered_names:
                continue
            rendered_names.add(key)
            inputs += f'  <input type="file" name="{html.escape(str(key), quote=True)}">\n'
        if post_data and not body_fields:
            try:
                post_json = json.loads(post_data)
                if isinstance(post_json, dict):
                    for key, val in post_json.items():
                        inputs += f'  <input name="{html.escape(str(key), quote=True)}" value="{html.escape(str(val), quote=True)}">\n'
            except Exception as exc:
                logger.debug("[SPA Crawler] API payload parse fallback for %s: %s", api["url"], exc)
                if 'name="' in post_data:
                    for field in set(re.findall(r'name="([^"]+)"', post_data)):
                        inputs += f'  <input name="{html.escape(field, quote=True)}" value="">\n'
                elif "=" in post_data:
                    for key, val in parse_qsl(post_data, keep_blank_values=True):
                        inputs += f'  <input name="{html.escape(str(key), quote=True)}" value="{html.escape(str(val), quote=True)}">\n'
        if not inputs.strip():
            continue
        html_method = "POST" if method in ("PUT", "PATCH", "DELETE") else method
        data_source = html.escape(str(api.get("source") or ""), quote=True)
        data_route = html.escape(str(api.get("route_context") or ""), quote=True)
        data_source_url = html.escape(str(api.get("source_url") or api.get("route_context") or ""), quote=True)
        data_depth = html.escape(str(api.get("depth", 0)), quote=True)
        response_headers_payload = dict(api.get("response_headers") or {})
        if not response_headers_payload and fallback_ct:
            response_headers_payload = {"content-type": fallback_ct}
        if "content-type" not in response_headers_payload and fallback_ct:
            response_headers_payload["content-type"] = fallback_ct
        data_resp_headers = html.escape(json.dumps(response_headers_payload, ensure_ascii=False), quote=True)
        default_server = str(getattr(engine, "default_server_name", "") or "")
        server_info_payload = fallback_server_info_for_api(api, default_server=default_server)
        data_server_info = html.escape(json.dumps(server_info_payload, ensure_ascii=False), quote=True)
        data_resp_ct = html.escape(str(fallback_ct or ""), quote=True)
        data_inferred = "true" if (method == "GET" and inferred_flag) else "false"
        synthesized += (
            f'<form action="{action}" method="{html_method}"{form_enctype_attr} '
            f'data-original-method="{method}" '
            f'data-content-type="{ct}" data-source-kind="{data_source}" '
            f'data-route-context="{data_route}" data-source-url="{data_source_url}" '
            f'data-depth="{data_depth}" data-response-headers="{data_resp_headers}" '
            f'data-server-info="{data_server_info}" data-response-content-type="{data_resp_ct}" '
            f'data-inferred="{data_inferred}">\n{inputs}</form>\n'
        )
        api_count += 1
        engine.metrics["apis_found"] += 1
    synthesized += "</div>\n"
    lower = final_html.lower()
    if "</body>" in lower:
        idx = lower.rfind("</body>")
        return final_html[:idx] + synthesized + final_html[idx:]
    return final_html + synthesized
