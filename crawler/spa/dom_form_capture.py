"""SPA 라우트 방문 시 DOM 폼 필드명을 observed_body_samples에 반영."""

from __future__ import annotations

import logging
from urllib.parse import parse_qsl, urlparse

from crawler.spa.capture_core import (
    dom_fields_should_map_to_query,
    path_key_from_url,
    register_observed_body_field_hints,
    register_observed_query_fields,
)
from parsers.body_field_inference import sanitize_field_map

logger = logging.getLogger(__name__)

_COLLECT_FORM_FIELDS_JS = """() => {
    const fields = {};
    const labels = {};
    const skipName = /^(csrf|_token|token|authenticity_token|submit|button|login|logout)$/i;
    const skipType = new Set(['submit', 'button', 'reset', 'image']);
    const idLike = /^[a-zA-Z_][a-zA-Z0-9_-]*$/;
    const dataAttrs = ['data-field', 'data-name', 'data-testid', 'data-test', 'data-cy'];

    function looksLikeUrl(t) {
        const s = String(t || '').trim().toLowerCase();
        return s.startsWith('http://') || s.startsWith('https://') || s.startsWith('//')
            || (s.includes('://') && s.length >= 10);
    }

    function inferFromSemanticLabel(text) {
        const t = String(text || '').trim();
        if (!t) return '';
        if (looksLikeUrl(t)) return 'url';
        if (/(?:external|remote|reference|fetch|proxy|webhook|callback|redirect|foreign|embed|avatar|image|logo|src|href|외부|참조|연동|링크|이미지)/i.test(t)
            && /(?:url|uri|link|endpoint|주소|링크)/i.test(t)) {
            return 'external_url';
        }
        if (/^(?:url|uri|link|href|src|endpoint)$/i.test(t)) return 'url';
        if (/\\b(?:e-?mail|email)\\b/i.test(t)) return 'email';
        if (/\\b(?:phone|mobile|tel|연락|전화)\\b/i.test(t)) return 'phone';
        if (/\\b(?:password|passwd|비밀)\\b/i.test(t)) return 'password';
        if (/\\b(?:username|user_name|아이디)\\b/i.test(t)) return 'username';
        if (/\\b(?:attachment|upload|첨부|파일)\\b/i.test(t)) return 'attachment';
        return '';
    }

    function slugify(text) {
        const raw = String(text || '').trim().slice(0, 80);
        if (!raw || looksLikeUrl(raw)) return '';
        const slug = raw
            .toLowerCase()
            .replace(/[^\\w\\s-]+/g, ' ')
            .replace(/[\\s-]+/g, '_')
            .replace(/^_+|_+$/g, '')
            .slice(0, 64);
        if (!slug || !/^[a-z][a-z0-9_]*$/.test(slug)) return '';
        if (/^(?:https?|http)_|_com_|example_com|localhost/.test(slug)) return '';
        return slug;
    }

    function labelTextForControl(el) {
        const id = (el.getAttribute('id') || '').trim();
        if (id) {
            try {
                const bound = document.querySelector(`label[for="${CSS.escape(id)}"]`);
                if (bound && bound.innerText) return bound.innerText.trim();
            } catch (e) {}
        }
        const parentLabel = el.closest('label');
        if (parentLabel && parentLabel.innerText) return parentLabel.innerText.trim();
        const aria = (el.getAttribute('aria-label') || '').trim();
        if (aria) return aria;
        // React/Vue 등: <label>텍스트</label><input> 형태의 형제 라벨
        let prev = el.previousElementSibling;
        if (prev && prev.tagName === 'LABEL' && prev.innerText) {
            return prev.innerText.trim();
        }
        // 같은 field-group 컨테이너 안의 첫 label (div > label + input 패턴)
        const group = el.closest('div, fieldset, section, li, p');
        if (group) {
            const labels = group.querySelectorAll(':scope > label');
            if (labels.length === 1 && labels[0].innerText) {
                return labels[0].innerText.trim();
            }
            for (const lbl of labels) {
                if (!lbl.innerText) continue;
                let node = lbl.nextElementSibling;
                while (node) {
                    if (node === el || node.contains(el)) {
                        return lbl.innerText.trim();
                    }
                    node = node.nextElementSibling;
                }
            }
        }
        return '';
    }

    function inferFieldName(el) {
        const explicit = (el.getAttribute('name') || '').trim();
        if (explicit) return explicit;

        const id = (el.getAttribute('id') || '').trim();
        if (id && idLike.test(id)) return id.replace(/-/g, '_');

        for (const attr of dataAttrs) {
            const v = (el.getAttribute(attr) || '').trim();
            if (!v) continue;
            const semantic = inferFromSemanticLabel(v);
            if (semantic) return semantic;
            const fromData = slugify(v) || (idLike.test(v) ? v.replace(/-/g, '_') : '');
            if (fromData) return fromData;
        }

        const label = labelTextForControl(el);
        const placeholder = (el.getAttribute('placeholder') || '').trim();
        const fromLabel = inferFromSemanticLabel(label);
        if (fromLabel) return fromLabel;

        const type = (el.getAttribute('type') || 'text').toLowerCase();
        const typeHints = { email: 'email', password: 'password', search: 'q', tel: 'phone', url: 'url' };
        if (typeHints[type]) return typeHints[type];

        // placeholder의 예시 URL(http://…)은 필드명이 아님 — 라벨 slug만 사용
        if (looksLikeUrl(placeholder)) {
            return slugify(label) || '';
        }
        return slugify(label) || slugify(placeholder);
    }

    function addField(name, value, el, labelHint) {
        const key = String(name || '').trim();
        if (!key || skipName.test(key)) return;
        const type = (el && (el.getAttribute('type') || 'text').toLowerCase()) || 'text';
        if (skipType.has(type)) return;
        if (el && (type === 'checkbox' || type === 'radio') && !el.checked) return;
        const val = String(value || '').slice(0, 500);
        if (!(key in fields) || !String(fields[key] || '').trim()) {
            fields[key] = val;
        }
        if (labelHint && !(key in labels)) {
            labels[key] = String(labelHint).slice(0, 200);
        }
    }

    document.querySelectorAll('input, textarea, select').forEach((el) => {
        const type = (el.getAttribute('type') || 'text').toLowerCase();
        if (type === 'hidden' || type === 'file') return;
        const label = labelTextForControl(el);
        const placeholder = (el.getAttribute('placeholder') || '').trim();
        const key = inferFieldName(el);
        if (key) addField(key, el.value, el, label || placeholder);
    });

    return { fields, labels };
}"""


def _normalize_dom_capture(raw: object) -> tuple[dict[str, str], dict[str, str]]:
    if not isinstance(raw, dict):
        return {}, {}

    if "fields" in raw or "labels" in raw:
        field_map = raw.get("fields") if isinstance(raw.get("fields"), dict) else {}
        label_map = raw.get("labels") if isinstance(raw.get("labels"), dict) else {}
    else:
        field_map = raw
        label_map = {}

    label_hints = {
        str(k): str(v)
        for k, v in label_map.items()
        if str(k).strip()
    }
    values = {
        str(k).strip(): str(v)[:500]
        for k, v in field_map.items()
        if str(k).strip()
    }
    return sanitize_field_map(values, label_hints=label_hints), label_hints


async def extract_visible_form_fields(page) -> tuple[dict[str, str], dict[str, str]]:
    try:
        raw = await page.evaluate(_COLLECT_FORM_FIELDS_JS)
    except Exception as exc:
        logger.debug("[SPA Crawler] DOM form field capture failed: %s", exc)
        return {}, {}
    return _normalize_dom_capture(raw)


def _route_api_path_keys_related(route_key: str, route_path: str, api_key: str, source_url: str) -> bool:
    source_key = path_key_from_url(source_url) if source_url.startswith("http") else source_url
    if route_key and (route_key in api_key or api_key.endswith(route_key)):
        return True
    if route_path and source_url:
        src_path = (urlparse(source_url).path or "").rstrip("/").lower()
        if src_path == route_path or route_path in src_path or src_path in route_path:
            return True
    if route_key and source_key and (route_key in source_key or source_key in route_key):
        return True
    if route_key.startswith("/api/") and route_key[4:] == api_key:
        return True
    if api_key.startswith("/api/") and api_key[4:] == route_key:
        return True
    return False


def _conventional_api_path_for_ui_route(route_path: str) -> str:
    """UI 경로 /foo → 관례적 API 경로 /api/foo (범용 SPA 패턴)."""
    normalized = (route_path or "").rstrip("/").lower()
    if not normalized or normalized.startswith("/api/"):
        return ""
    return f"/api{normalized}"


def register_route_query_params_from_url(engine, route_url: str) -> int:
    """
    클라이언트 라우팅으로 URL 쿼리가 붙은 경우(예: navigate('/page?x=1')),
    UI 경로 및 관련 API path_key에 쿼리 샘플을 등록한다.
    """
    parsed = urlparse(route_url)
    if not parsed.query:
        return 0
    fields = {
        str(k).strip(): str(v)[:500]
        for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        if str(k).strip()
    }
    if not fields:
        return 0

    route_key = path_key_from_url(route_url)
    route_path = (parsed.path or "").rstrip("/").lower()
    updated = register_observed_query_fields(engine, route_key, fields)

    api_path = _conventional_api_path_for_ui_route(route_path)
    if api_path:
        updated += register_observed_query_fields(engine, api_path, fields)

    for entry in getattr(engine, "api_endpoints", {}).values():
        api_key = path_key_from_url(str(entry.get("url") or ""))
        source_url = str(entry.get("source_url") or "")
        if _route_api_path_keys_related(route_key, route_path, api_key, source_url):
            updated += register_observed_query_fields(engine, api_key, fields)

    return updated


def register_dom_fields_for_route(
    engine,
    route_url: str,
    fields: dict[str, str],
    *,
    label_hints: dict[str, str] | None = None,
) -> int:
    """
    현재 클라이언트 라우트의 input/textarea name을 관련 API path_key에 병합.
    읽기 전용 GET API는 body 대신 query 샘플로 매핑한다.
    """
    fields = sanitize_field_map(fields, label_hints=label_hints)
    if not fields:
        return 0

    body_samples_map = getattr(engine, "observed_body_samples", None)
    if body_samples_map is None:
        engine.observed_body_samples = {}
        body_samples_map = engine.observed_body_samples
    dom_body_keys = getattr(engine, "dom_inferred_body_path_keys", None)
    if dom_body_keys is None:
        engine.dom_inferred_body_path_keys = set()
        dom_body_keys = engine.dom_inferred_body_path_keys

    route_key = path_key_from_url(route_url)
    route_path = (urlparse(route_url).path or "").rstrip("/").lower()
    updated = 0

    def merge_into_body(path_key: str) -> None:
        nonlocal updated
        if not path_key:
            return
        bucket = dict(body_samples_map.get(path_key) or {})
        before = len(bucket)
        for key, value in fields.items():
            key_str = str(key).strip()
            if not key_str:
                continue
            if key_str not in bucket or not str(bucket.get(key_str) or "").strip():
                bucket[key_str] = str(value)
        if len(bucket) > before or (before == 0 and bucket):
            body_samples_map[path_key] = sanitize_field_map(bucket, label_hints=label_hints)
            dom_body_keys.add(path_key)
            updated += 1
        register_observed_body_field_hints(engine, path_key, fields.keys())

    def merge_into_query(path_key: str) -> None:
        nonlocal updated
        if not path_key:
            return
        if register_observed_query_fields(engine, path_key, fields):
            updated += 1

    def merge_for_path(path_key: str) -> None:
        if dom_fields_should_map_to_query(engine, path_key):
            merge_into_query(path_key)
        else:
            merge_into_body(path_key)

    merge_for_path(route_key)

    api_path = _conventional_api_path_for_ui_route(route_path)
    if api_path:
        merge_for_path(api_path)

    for entry in getattr(engine, "api_endpoints", {}).values():
        api_url = str(entry.get("url") or "")
        api_key = path_key_from_url(api_url)
        source_url = str(entry.get("source_url") or "")
        if _route_api_path_keys_related(route_key, route_path, api_key, source_url):
            merge_for_path(api_key)

    return updated


async def capture_and_register_dom_fields(engine, page) -> None:
    fields, label_hints = await extract_visible_form_fields(page)
    if not fields:
        return
    route_url = str(getattr(page, "url", "") or getattr(engine, "current_route_url", "") or "")
    count = register_dom_fields_for_route(engine, route_url, fields, label_hints=label_hints)
    if count:
        logger.debug(
            "[SPA Crawler] DOM form fields (%s keys) linked to %s API path(s) on %s",
            len(fields),
            count,
            route_url,
        )
