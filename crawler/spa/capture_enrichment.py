"""Endpoint enrichment, normalization, and prioritization."""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlparse, urlunparse

from parsers.body_field_inference import (
    is_plausible_field_name,
    merge_path_inferred_fields,
    sanitize_field_map,
)
from parsers.http_method_inference import infer_body_params_from_path, infer_http_method_from_path

from crawler.spa.capture_core import (
    _MUTATING_METHODS,
    api_has_live_signal,
    api_source_rank,
    drop_get_stubs_for_path,
    parse_payload_fields,
    path_key_from_url,
    record_api_candidate,
    serialize_body_fields,
)
from crawler.spa.path_family import path_keys_share_body_field_family

_DELETE_SEGMENT_RE = re.compile(r"^delete[a-z0-9_-]*$", re.IGNORECASE)
_MUTATION_HINT_SEGMENTS = frozenset(
    {
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
        "confirm",
        "process",
        "checkout",
        "cart",
        "wishlist",
        "comment",
        "review",
        "reviews",
        "board",
    }
)


def _path_segments(path: str) -> tuple[str, ...]:
    return tuple(seg for seg in str(path or "").split("/") if seg)


def _looks_like_mutating_api_path(path: str) -> bool:
    path_norm = (path or "/").rstrip("/")
    if not path_norm.startswith("/api/"):
        return False
    segments = [seg.lower() for seg in _path_segments(path_norm)]
    if not segments:
        return False
    if segments[-1] in _MUTATION_HINT_SEGMENTS:
        return True
    return bool(set(segments) & _MUTATION_HINT_SEGMENTS)


def _should_promote_get_api_to_post(engine, entry: dict) -> bool:
    url = str(entry.get("url") or "")
    parsed = urlparse(url)
    path = (parsed.path or "").rstrip("/") or "/"
    if parsed.query:
        return False
    if not path.startswith("/api/"):
        return False

    req_ct = str(entry.get("req_content_type") or "").lower()
    resp_ct = str(entry.get("content_type") or "").lower()
    has_json_signal = "json" in req_ct or "json" in resp_ct
    if not has_json_signal and not _looks_like_mutating_api_path(path):
        return False

    path_key = path_key_from_url(url)
    observed_body = getattr(engine, "observed_body_samples", None) or {}
    if observed_body.get(path_key):
        return True

    # If there is already any mutating sibling for the same path family, follow it.
    parent = path.rsplit("/", 1)[0] if "/" in path.strip("/") else path
    parent = parent or "/"
    for sibling in engine.api_endpoints.values():
        sibling_url = str(sibling.get("url") or "")
        sibling_path = (urlparse(sibling_url).path or "").rstrip("/") or "/"
        if not (sibling_path == parent or sibling_path.startswith(f"{parent}/")):
            continue
        sibling_method = str(sibling.get("method") or "GET").upper()
        if sibling_method in _MUTATING_METHODS:
            return True

    return _looks_like_mutating_api_path(path)


def _candidate_delete_actions_for_resource(engine, resource_path: str) -> tuple[str, ...]:
    actions = {"delete"}
    resource_norm = (resource_path or "/").rstrip("/")
    for entry in getattr(engine, "api_endpoints", {}).values():
        parsed = urlparse(str(entry.get("url") or ""))
        entry_path = (parsed.path or "").rstrip("/")
        if not entry_path:
            continue
        if not (entry_path == resource_norm or entry_path.startswith(f"{resource_norm}/")):
            continue
        tail = entry_path[len(resource_norm):].strip("/")
        if not tail or "/" in tail:
            continue
        if _DELETE_SEGMENT_RE.match(tail):
            actions.add(tail)
    return tuple(sorted(actions))


def _infer_delete_params_from_context(
    path: str,
    params: dict[str, str],
    observed_query: dict[str, dict[str, str]],
    observed_body: dict[str, dict[str, str]],
) -> dict[str, str]:
    inferred: dict[str, str] = {}
    path_segments = tuple(seg.lower() for seg in _path_segments(path))
    common_keys = ("id", "post_id", "comment_id", "review_id", "book_id", "item_id", "cart_id", "wishlist_id")
    for key in common_keys:
        value = str(params.get(key) or "").strip()
        if value:
            inferred[key] = value

    key = path_key_from_url(path)
    for sample_map in (observed_query.get(key) or {}, observed_body.get(key) or {}):
        for sample_key, sample_val in sample_map.items():
            sample_key_str = str(sample_key).strip()
            if sample_key_str in common_keys and sample_key_str not in inferred:
                inferred[sample_key_str] = str(sample_val or "")

    if "comment" in path_segments and "post_id" not in inferred:
        candidate = str(params.get("post_id") or params.get("id") or "").strip()
        if candidate:
            inferred["post_id"] = candidate
    if ("cart" in path_segments or "wishlist" in path_segments) and "book_id" not in inferred:
        candidate = str(params.get("book_id") or params.get("id") or "").strip()
        if candidate:
            inferred["book_id"] = candidate
    if not inferred:
        inferred["id"] = str(params.get("id") or "")
    return inferred


def representative_url_for_path(engine, path_key: str) -> str:
    for api in engine.api_endpoints.values():
        if path_key_from_url(api.get("url") or "") != path_key:
            continue
        parsed = urlparse(api["url"])
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    target = str(getattr(engine, "target_url", "") or "").strip()
    if not target:
        return ""
    parsed = urlparse(target)
    path = path_key if path_key.startswith("/") else f"/{path_key}"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def canonical_api_path(path: str) -> str:
    p = str(path or "").rstrip("/") or "/"
    if p.startswith("/api/"):
        return p[4:] or "/"
    return p


def _path_relation_score(candidate_path: str, target_path: str) -> int:
    c = (candidate_path or "/").rstrip("/") or "/"
    t = (target_path or "/").rstrip("/") or "/"
    if c == t:
        return 8
    if c.startswith(f"{t}/") or t.startswith(f"{c}/"):
        return 5
    c_seg = [seg for seg in c.split("/") if seg]
    t_seg = [seg for seg in t.split("/") if seg]
    if not c_seg or not t_seg:
        return 0
    overlap = len(set(c_seg) & set(t_seg))
    if overlap >= 2:
        return 3
    if overlap == 1:
        return 1
    return 0


def _collect_source_candidates(engine) -> list[str]:
    target_base = str(getattr(engine, "target_url", "") or "")
    parsed_target = urlparse(target_base) if target_base else None
    candidates: list[str] = []
    for entry in engine.api_endpoints.values():
        raw = str(entry.get("source_url") or "")
        if raw:
            candidates.append(raw)
        route_ctx = str(entry.get("route_context") or "").strip()
        if route_ctx and parsed_target is not None:
            ctx_path = route_ctx.split("#", 1)[0]
            if not ctx_path.startswith("/"):
                ctx_path = "/" + ctx_path
            candidates.append(
                urlunparse((parsed_target.scheme, parsed_target.netloc, ctx_path, "", "", ""))
            )
    for raw in getattr(engine, "found_urls", set()) or set():
        if raw:
            candidates.append(str(raw))
    return candidates


def _entry_param_names(engine, entry: dict) -> set[str]:
    names: set[str] = set()
    entry_url = str(entry.get("url") or "")
    parsed = urlparse(entry_url)
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        key_str = str(key).strip()
        if key_str:
            names.add(key_str)
    body = parse_payload_fields(entry.get("post_data") or "", entry.get("req_content_type") or "")
    names.update(str(k).strip() for k in body.keys() if str(k).strip())
    path_key = path_key_from_url(entry_url)
    observed_q = (getattr(engine, "observed_query_samples", None) or {}).get(path_key) or {}
    observed_b = (getattr(engine, "observed_body_samples", None) or {}).get(path_key) or {}
    names.update(str(k).strip() for k in observed_q.keys() if str(k).strip())
    names.update(str(k).strip() for k in observed_b.keys() if str(k).strip())
    return names


def _is_listing_source_query(query: str) -> bool:
    if not query:
        return False
    keys = {str(k).strip().lower() for k, _ in parse_qsl(query, keep_blank_values=True) if str(k).strip()}
    if not keys:
        return False
    listing_keys = {"type", "category", "search", "q", "query", "keyword", "page", "limit", "offset", "sort"}
    return bool(keys) and bool(keys & listing_keys) and "id" not in keys


def _path_intent_hint(path: str) -> tuple[bool, bool]:
    segs = [seg.lower() for seg in _path_segments(path)]
    mutation = bool(set(segs) & {"comment", "edit", "delete", "reviews", "review", "checkout", "process", "confirm"})
    viewish = bool(set(segs) & {"view", "detail", "item"}) or path.rstrip("/").endswith("/view")
    return mutation, viewish


def best_source_url_for_path(engine, path_key: str, *, entry: dict | None = None) -> str:
    canonical = canonical_api_path(path_key)
    parent = canonical.rsplit("/", 1)[0] if "/" in canonical.strip("/") else canonical
    parent = parent or "/"
    candidates = _collect_source_candidates(engine)
    param_names = _entry_param_names(engine, entry) if entry is not None else set()
    entry_path = (urlparse(str((entry or {}).get("url") or "")).path or "").rstrip("/") or "/"
    entry_mutation_hint, _ = _path_intent_hint(entry_path)
    needs_id_context = bool(param_names & {"id", "post_id", "comment_id", "review_id", "book_id", "order_id"})

    scored: list[tuple[int, str]] = []
    for raw in candidates:
        try:
            parsed = urlparse(raw)
        except Exception:
            continue
        p = (parsed.path or "/").rstrip("/") or "/"
        q = parsed.query or ""

        rel = _path_relation_score(p, canonical)
        parent_rel = _path_relation_score(p, parent)
        score = max(rel, parent_rel)
        # Reject unrelated candidates to prevent one hot route dominating everything.
        if score <= 0:
            continue
        if canonical != path_key and p == path_key:
            score += 2
        if q:
            score += 2
        if param_names and q:
            q_keys = {str(k).strip() for k, _ in parse_qsl(q, keep_blank_values=True) if str(k).strip()}
            shared = len(param_names & q_keys)
            if shared:
                # Prefer source routes whose query keys explain this API's parameters.
                score += (shared * 3)
            if "id" in q_keys:
                score += 1
            if needs_id_context and "id" not in q_keys and ("post_id" not in q_keys and "book_id" not in q_keys):
                score -= 3
        source_mutation_hint, source_view_hint = _path_intent_hint(p)
        if entry_mutation_hint and source_view_hint:
            score += 2
        if entry_mutation_hint and q and _is_listing_source_query(q):
            score -= 4
        if entry_mutation_hint and source_mutation_hint and q and "id=" in q.lower():
            score += 1
        if "type=" in q:
            score += 1
        if score > 0:
            scored.append((score, raw))

    if scored:
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[0][1]
    return ""


def enrich_source_urls(engine) -> int:
    changed = 0
    parsed_target = urlparse(str(getattr(engine, "target_url", "") or "")) if getattr(engine, "target_url", None) else None

    def _fallback_source_for_path(pkey: str) -> str:
        if parsed_target is None:
            return ""
        canonical = canonical_api_path(pkey)
        parent = canonical.rsplit("/", 1)[0] if "/" in canonical.strip("/") else canonical
        parent = parent or "/"
        return urlunparse((parsed_target.scheme, parsed_target.netloc, parent, "", "", ""))

    for entry in engine.api_endpoints.values():
        path_key = path_key_from_url(entry.get("url") or "")
        best = best_source_url_for_path(engine, path_key, entry=entry)
        current = str(entry.get("source_url") or "").strip()
        if best and current != best:
            # Replace missing or weak/unrelated source_url with best path-related route.
            if not current:
                entry["source_url"] = best
                changed += 1
                continue
            current_path = (urlparse(current).path or "/").rstrip("/") or "/"
            target_path = canonical_api_path(path_key)
            if _path_relation_score(current_path, target_path) < _path_relation_score((urlparse(best).path or "/"), target_path):
                entry["source_url"] = best
                changed += 1
        elif best and not current:
            entry["source_url"] = best
            changed += 1
        elif not best:
            # If current is empty/root, fallback to a path-related parent route.
            current_path = (urlparse(current).path or "/").rstrip("/") or "/"
            if not current or current_path == "/":
                fb = _fallback_source_for_path(path_key)
                if fb and fb != current:
                    entry["source_url"] = fb
                    changed += 1
    return changed


def merge_observed_body_fields_for_family(
    engine,
    path_key: str,
    *,
    local_fields: dict[str, str] | None = None,
) -> dict[str, str]:
    """
    같은 API 리소스 트리(예: /api/checkout/*)에서 관측된 body 필드를 합친다.
    SPA는 confirm/process 등 형제 엔드포인트마다 XHR 본문이 달라 한 path_key만으로는 필드가 비는 경우가 많다.
    """
    samples = getattr(engine, "observed_body_samples", None) or {}
    merged = sanitize_field_map(local_fields)
    merged.update(sanitize_field_map(samples.get(path_key) or {}))

    for sample_key, fields in samples.items():
        if not fields or sample_key == path_key:
            continue
        if not path_keys_share_body_field_family(path_key, sample_key):
            continue
        for key, value in sanitize_field_map(fields).items():
            if key not in merged or not str(merged.get(key) or "").strip():
                merged[key] = str(value)
    return merged


def resolve_mutating_body_fields(
    engine,
    path_key: str,
    *,
    local_fields: dict[str, str] | None = None,
    source_url: str = "",
    url: str = "",
) -> dict[str, str]:
    """
    XHR/DOM 관측 + 리소스 family + source URL + 경로 세그먼트 힌트를 순서대로 병합.
    관측값은 유지하고, 누락된 키만 보강한다 (범용 SPA surface 구축).
    """
    body_samples = getattr(engine, "observed_body_samples", None) or {}
    seed = dict(local_fields or {})
    if not seed:
        seed = dict(body_samples.get(path_key) or {})
    fields = merge_observed_body_fields_for_family(
        engine,
        path_key,
        local_fields=seed,
    )
    if not fields and url:
        fields = infer_body_params_from_path(url)
    fields = hydrate_fields_from_source_context(fields, source_url)
    return merge_path_inferred_fields(sanitize_field_map(fields), path_key)


def hydrate_fields_from_source_context(fields: dict[str, str], source_url: str) -> dict[str, str]:
    if not fields or not source_url:
        return fields
    try:
        parsed = urlparse(source_url)
    except Exception:
        return fields
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not q:
        return fields
    hydrated = dict(fields)
    for key in list(hydrated.keys()):
        if str(hydrated.get(key) or "").strip():
            continue
        mapped = str(q.get(key) or "").strip()
        if mapped:
            hydrated[key] = mapped
    return hydrated


def infer_companion_action_endpoints(engine) -> int:
    added = 0
    snapshots = list(engine.api_endpoints.values())
    for api in snapshots:
        parsed = urlparse(str(api.get("url") or ""))
        path = (parsed.path or "").rstrip("/")
        if not path:
            continue
        source_url = str(api.get("source_url") or "")
        method = str(api.get("method") or "GET").upper()
        params = parse_payload_fields(api.get("post_data") or "", api.get("req_content_type") or "")
        if not params:
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not params:
            params = dict((getattr(engine, "observed_query_samples", None) or {}).get(path_key_from_url(api.get("url") or "")) or {})
        observed_query = getattr(engine, "observed_query_samples", None) or {}
        observed_body = getattr(engine, "observed_body_samples", None) or {}

        if path.endswith("/view") or path.endswith("/edit"):
            inferred_id = str(params.get("id") or "").strip()
            if "id" in params:
                delete_path = path.rsplit("/", 1)[0] + "/delete"
                delete_url = urlunparse((parsed.scheme, parsed.netloc, delete_path, "", "", ""))
                _, created = record_api_candidate(
                    engine,
                    method="GET",
                    url=delete_url,
                    req_content_type="",
                    post_data=None,
                    source="companion-inferred",
                    source_url=source_url,
                )
                if created:
                    obs = getattr(engine, "observed_query_samples", None) or {}
                    key = path_key_from_url(delete_url)
                    if key not in obs:
                        obs[key] = {"id": inferred_id}
                        engine.observed_query_samples = obs
                    added += 1

        if path.endswith("/logs"):
            view_url = urlunparse((parsed.scheme, parsed.netloc, path + "/view", "", "", ""))
            _, created = record_api_candidate(
                engine,
                method="GET",
                url=view_url,
                req_content_type="",
                post_data=None,
                source="companion-inferred",
                source_url=source_url,
            )
            if created:
                obs = getattr(engine, "observed_query_samples", None) or {}
                key = path_key_from_url(view_url)
                if key not in obs:
                    obs[key] = {"file": ""}
                    engine.observed_query_samples = obs
                added += 1

        if method in _MUTATING_METHODS and path.endswith("/add"):
            delete_path = path.rsplit("/", 1)[0] + "/delete"
            delete_url = urlunparse((parsed.scheme, parsed.netloc, delete_path, "", "", ""))
            _, created = record_api_candidate(
                engine,
                method="POST",
                url=delete_url,
                req_content_type="application/json",
                post_data=json.dumps({"id": ""}),
                source="companion-inferred",
                source_url=source_url,
            )
            if created:
                added += 1
        # Generic companion delete inference:
        # infer sibling delete endpoints for mutating resources and common route families.
        path_segments = _path_segments(path)
        path_segment_set = {seg.lower() for seg in path_segments}
        last_seg = (path_segments[-1].lower() if path_segments else "")
        skip_delete_infer = bool(_DELETE_SEGMENT_RE.match(last_seg))
        should_infer_delete = (
            method in _MUTATING_METHODS
            or last_seg in {"view", "edit", "write", "add", "create", "comment"}
            or bool(path_segment_set & {"board", "comment", "reviews", "review", "cart", "wishlist"})
        )
        if not skip_delete_infer and should_infer_delete:
            if last_seg in {"view", "edit", "write", "add", "create", "comment"}:
                resource_path = path.rsplit("/", 1)[0] if "/" in path.strip("/") else path
            else:
                resource_path = path
            delete_params = _infer_delete_params_from_context(path, params, observed_query, observed_body)
            if "board" in path_segment_set:
                for board_delete_path in ("/board/delete", f"{resource_path.rstrip('/')}/delete"):
                    delete_url = urlunparse((parsed.scheme, parsed.netloc, board_delete_path, "", "", ""))
                    _, created = record_api_candidate(
                        engine,
                        method="GET",
                        url=delete_url,
                        req_content_type="",
                        post_data=None,
                        source="companion-inferred",
                        source_url=source_url,
                    )
                    if created:
                        obs = getattr(engine, "observed_query_samples", None) or {}
                        key = path_key_from_url(delete_url)
                        if key not in obs:
                            obs[key] = dict(delete_params)
                            engine.observed_query_samples = obs
                        added += 1

            for action in _candidate_delete_actions_for_resource(engine, resource_path):
                delete_path = f"{resource_path.rstrip('/')}/{action}"
                delete_url = urlunparse((parsed.scheme, parsed.netloc, delete_path, "", "", ""))
                _, created = record_api_candidate(
                    engine,
                    method="POST",
                    url=delete_url,
                    req_content_type="application/json",
                    post_data=json.dumps(dict(delete_params), ensure_ascii=False),
                    source="companion-inferred",
                    source_url=source_url,
                )
                if created:
                    added += 1
    return added


def path_has_mutating_with_body(engine, path_key: str) -> bool:
    for entry in list(engine.api_endpoints.values()):
        if path_key_from_url(entry.get("url") or "") != path_key:
            continue
        if str(entry.get("method") or "GET").upper() not in _MUTATING_METHODS:
            continue
        if entry.get("post_data"):
            return True
        if parse_payload_fields(entry.get("post_data") or "", entry.get("req_content_type") or ""):
            return True
    return False


def normalize_mutating_path_endpoints(engine) -> int:
    changed = 0
    body_samples = getattr(engine, "observed_body_samples", None) or {}
    body_cts = getattr(engine, "observed_body_content_types", None) or {}

    # Iterate over a snapshot because this loop may drop/replace endpoints.
    for entry in list(engine.api_endpoints.values()):
        url = str(entry.get("url") or "")
        method_upper = str(entry.get("method") or "GET").upper()
        promote_get_api = method_upper == "GET" and _should_promote_get_api_to_post(engine, entry)
        if infer_http_method_from_path(url) != "POST" and not promote_get_api:
            continue
        path_key = path_key_from_url(url)
        source_url = best_source_url_for_path(engine, path_key) or str(entry.get("source_url") or "")
        existing_fields = parse_payload_fields(
            entry.get("post_data") or "", entry.get("req_content_type") or ""
        )
        fields = resolve_mutating_body_fields(
            engine,
            path_key,
            local_fields=existing_fields,
            source_url=source_url,
            url=url,
        )
        if not fields and promote_get_api:
            fields = {"id": ""}
        if not fields:
            continue
        content_type = body_cts.get(path_key, "application/json")
        post_data, req_ct = serialize_body_fields(fields, content_type)
        file_map = getattr(engine, "observed_body_file_fields", None) or {}
        path_file_fields = sorted(file_map.get(path_key) or ())
        if path_file_fields:
            req_ct = "multipart/form-data"
            entry["file_fields"] = path_file_fields

        prior_post = entry.get("post_data")
        entry["method"] = "POST"
        entry["post_data"] = post_data
        entry["req_content_type"] = req_ct
        if prior_post != post_data:
            source = str(entry.get("source") or "")
            if source in ("js-static", "") and not existing_fields:
                entry["source"] = "path-inferred"
            changed += 1
        if source_url and not str(entry.get("source_url") or "").strip():
            entry["source_url"] = source_url
        drop_get_stubs_for_path(engine, path_key)
    return changed


def enrich_api_endpoints_from_observations(engine) -> int:
    body_samples = getattr(engine, "observed_body_samples", None) or {}
    body_cts = getattr(engine, "observed_body_content_types", None) or {}
    if not body_samples:
        return 0
    added = 0
    for path_key, fields in body_samples.items():
        if not fields:
            continue
        content_type = body_cts.get(path_key, "application/json")
        post_data, req_content_type = serialize_body_fields(fields, content_type)
        file_map = getattr(engine, "observed_body_file_fields", None) or {}
        path_file_fields = sorted(file_map.get(path_key) or ())
        if path_file_fields:
            req_content_type = "multipart/form-data"

        for entry in list(engine.api_endpoints.values()):
            if path_key_from_url(entry.get("url") or "") != path_key:
                continue
            if str(entry.get("method") or "GET").upper() not in _MUTATING_METHODS:
                continue
            if entry.get("post_data"):
                existing = parse_payload_fields(
                    entry.get("post_data") or "", entry.get("req_content_type") or ""
                )
                merged = resolve_mutating_body_fields(
                    engine,
                    path_key,
                    local_fields=existing,
                    source_url=str(entry.get("source_url") or ""),
                    url=str(entry.get("url") or ""),
                )
                merged_post, merged_ct = serialize_body_fields(merged, content_type)
                if merged_post != entry.get("post_data"):
                    entry["post_data"] = merged_post
                    entry["req_content_type"] = merged_ct
                    added += 1
                continue
            entry["post_data"] = post_data
            entry["req_content_type"] = req_content_type
            if path_file_fields:
                entry["file_fields"] = path_file_fields
            if str(entry.get("source") or "") == "js-static":
                entry["source"] = "observed-body"

        if path_has_mutating_with_body(engine, path_key):
            drop_get_stubs_for_path(engine, path_key)
            continue

        url = representative_url_for_path(engine, path_key)
        if not url:
            continue
        _, created = record_api_candidate(
            engine,
            method="POST",
            url=url,
            post_data=post_data,
            req_content_type=req_content_type,
            source="observed-body",
        )
        if created:
            added += 1
        drop_get_stubs_for_path(engine, path_key)
    return added


def fallback_content_type_for_api(api: dict) -> str:
    explicit = str(api.get("content_type") or "").strip().lower()
    if explicit and explicit != "unknown":
        return explicit
    req_ct = str(api.get("req_content_type") or "").strip().lower()
    if req_ct:
        return req_ct.split(";", 1)[0].strip()
    method = str(api.get("method") or "GET").upper()
    parsed = urlparse(str(api.get("url") or ""))
    path = (parsed.path or "").lower()
    if method in _MUTATING_METHODS or "/api/" in path:
        return "application/json"
    return "text/html"


def fallback_server_info_for_api(api: dict, default_server: str = "") -> dict[str, str]:
    existing = api.get("server_info")
    if isinstance(existing, dict) and existing:
        return {str(k): str(v) for k, v in existing.items()}
    if default_server:
        return {"web_server": default_server}
    return {}


def collect_global_response_metadata(engine) -> tuple[dict[str, str], dict[str, str]]:
    server_counter: dict[str, int] = {}
    content_counter: dict[str, int] = {}

    for api in list(engine.api_endpoints.values()):
        headers = api.get("response_headers") or {}
        if isinstance(headers, dict):
            server_name = str(headers.get("server") or headers.get("x-powered-by") or "").strip()
            if server_name:
                server_counter[server_name] = server_counter.get(server_name, 0) + 1
            ct = str(headers.get("content-type") or "").strip().lower()
            if ct:
                content_counter[ct] = content_counter.get(ct, 0) + 1
        fallback_ct = fallback_content_type_for_api(api)
        if fallback_ct:
            content_counter[fallback_ct] = content_counter.get(fallback_ct, 0) + 1

    page_headers: dict[str, str] = {}
    page_server_info: dict[str, str] = {}
    if content_counter:
        best_ct = max(content_counter.items(), key=lambda kv: kv[1])[0]
        if best_ct:
            page_headers["content-type"] = best_ct
    if server_counter:
        best_server = max(server_counter.items(), key=lambda kv: kv[1])[0]
        if best_server:
            page_headers["server"] = best_server
            page_server_info["web_server"] = best_server
    return page_headers, page_server_info


def score_api_endpoint(engine, api: dict) -> tuple[int, int, int, int]:
    method = str(api.get("method") or "GET").upper()
    method_rank = 4 if method in _MUTATING_METHODS else 1
    source_rank = api_source_rank(str(api.get("source") or ""))
    signal_rank = 1 if api_has_live_signal(engine, api) else 0
    parsed = urlparse(api.get("url") or "")
    param_rank = len(parse_qsl(parsed.query, keep_blank_values=True))
    if api.get("post_data"):
        param_rank += len(parse_payload_fields(api["post_data"], api.get("req_content_type") or ""))
    path_key = path_key_from_url(api.get("url") or "")
    param_rank += len((getattr(engine, "observed_query_samples", None) or {}).get(path_key) or {})
    param_rank += len((getattr(engine, "observed_body_samples", None) or {}).get(path_key) or {})
    return (method_rank, source_rank, signal_rank, param_rank)


def prioritize_api_endpoints(engine) -> list[dict]:
    by_path: dict[str, list[dict]] = {}
    for api in list(engine.api_endpoints.values()):
        path_key = path_key_from_url(api.get("url") or "")
        by_path.setdefault(path_key, []).append(api)
    selected: list[dict] = []
    for path_key, group in by_path.items():
        mutating = [api for api in group if str(api.get("method") or "").upper() in _MUTATING_METHODS]
        gets = [api for api in group if str(api.get("method") or "GET").upper() == "GET"]
        body_observed = bool((getattr(engine, "observed_body_samples", None) or {}).get(path_key))
        if mutating:
            selected.append(max(mutating, key=lambda api: score_api_endpoint(engine, api)))
            if body_observed:
                continue
        if not gets:
            continue
        best_get = max(gets, key=lambda api: score_api_endpoint(engine, api))
        if mutating and not api_has_live_signal(engine, best_get):
            continue
        if body_observed and not urlparse(best_get.get("url") or "").query:
            continue
        selected.append(best_get)
    selected.sort(key=lambda api: score_api_endpoint(engine, api), reverse=True)
    return selected


async def probe_endpoint_methods_precise(engine, context) -> int:
    updated = 0
    for api in list(engine.api_endpoints.values()):
        method = str(api.get("method") or "GET").upper()
        url = str(api.get("url") or "")
        if method != "GET" or infer_http_method_from_path(url) == "GET":
            continue
        try:
            resp = await context.request.fetch(url, method="OPTIONS", timeout=3500)
        except Exception:
            continue
        allow = str(resp.headers.get("allow", "")).upper()
        if not any(token in allow for token in ("POST", "PUT", "PATCH", "DELETE")):
            continue
        body_fields = infer_body_params_from_path(url)
        if not body_fields:
            continue
        post_data, req_ct = serialize_body_fields(body_fields, "application/json")
        api["method"] = "POST"
        api["post_data"] = post_data
        api["req_content_type"] = req_ct
        api["source"] = "options-probed"
        drop_get_stubs_for_path(engine, path_key_from_url(url))
        updated += 1
    return updated
