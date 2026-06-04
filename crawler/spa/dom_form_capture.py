"""SPA 라우트 방문 시 DOM 폼 필드명을 observed_body_samples에 반영."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from crawler.spa.capture_core import path_key_from_url, register_observed_body_field_hints

logger = logging.getLogger(__name__)

_COLLECT_FORM_FIELDS_JS = """() => {
    const fields = {};
    const skipName = /^(csrf|_token|token|authenticity_token|submit|button|login|logout)$/i;
    const skipType = new Set(['submit', 'button', 'reset', 'image']);
    const idLike = /^[a-zA-Z_][a-zA-Z0-9_-]*$/;
    const dataAttrs = ['data-field', 'data-name', 'data-testid', 'data-test', 'data-cy'];

    function slugify(text) {
        const raw = String(text || '').trim().slice(0, 80);
        if (!raw) return '';
        const slug = raw
            .toLowerCase()
            .replace(/[^\\w\\s-]+/g, ' ')
            .replace(/[\\s-]+/g, '_')
            .replace(/^_+|_+$/g, '')
            .slice(0, 64);
        return slug && /^[a-z][a-z0-9_]*$/.test(slug) ? slug : '';
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
        const placeholder = (el.getAttribute('placeholder') || '').trim();
        if (placeholder) return placeholder;
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
            const fromData = slugify(v) || (idLike.test(v) ? v.replace(/-/g, '_') : '');
            if (fromData) return fromData;
        }

        const type = (el.getAttribute('type') || 'text').toLowerCase();
        const typeHints = { email: 'email', password: 'password', search: 'q', tel: 'phone', url: 'url' };
        if (typeHints[type]) return typeHints[type];

        return slugify(labelTextForControl(el));
    }

    function addField(name, value, el) {
        const key = String(name || '').trim();
        if (!key || skipName.test(key)) return;
        const type = (el && (el.getAttribute('type') || 'text').toLowerCase()) || 'text';
        if (skipType.has(type)) return;
        if (el && (type === 'checkbox' || type === 'radio') && !el.checked) return;
        const val = String(value || '').slice(0, 500);
        if (!(key in fields) || !String(fields[key] || '').trim()) {
            fields[key] = val;
        }
    }

    document.querySelectorAll('input, textarea, select').forEach((el) => {
        const type = (el.getAttribute('type') || 'text').toLowerCase();
        if (type === 'hidden' || type === 'file') return;
        const key = inferFieldName(el);
        if (key) addField(key, el.value, el);
    });

    return fields;
}"""


async def extract_visible_form_fields(page) -> dict[str, str]:
    try:
        raw = await page.evaluate(_COLLECT_FORM_FIELDS_JS)
    except Exception as exc:
        logger.debug("[SPA Crawler] DOM form field capture failed: %s", exc)
        return {}
    if not isinstance(raw, dict):
        return {}
    return {
        str(k).strip(): str(v)[:500]
        for k, v in raw.items()
        if str(k).strip()
    }


def register_dom_fields_for_route(engine, route_url: str, fields: dict[str, str]) -> int:
    """
    현재 클라이언트 라우트의 input/textarea name을 관련 API path_key에 병합.
    React controlled form은 XHR 전까지 body 샘플이 비는 경우가 많다.
    """
    if not fields:
        return 0

    samples_map = getattr(engine, "observed_body_samples", None)
    if samples_map is None:
        engine.observed_body_samples = {}
        samples_map = engine.observed_body_samples

    route_key = path_key_from_url(route_url)
    route_path = (urlparse(route_url).path or "").rstrip("/").lower()
    updated = 0

    def merge_into(path_key: str) -> None:
        nonlocal updated
        if not path_key:
            return
        bucket = dict(samples_map.get(path_key) or {})
        before = len(bucket)
        for key, value in fields.items():
            key_str = str(key).strip()
            if not key_str:
                continue
            if key_str not in bucket or not str(bucket.get(key_str) or "").strip():
                bucket[key_str] = str(value)
        if len(bucket) > before or (before == 0 and bucket):
            samples_map[path_key] = bucket
            updated += 1
        register_observed_body_field_hints(engine, path_key, fields.keys())

    merge_into(route_key)

    for entry in getattr(engine, "api_endpoints", {}).values():
        api_url = str(entry.get("url") or "")
        api_key = path_key_from_url(api_url)
        source_url = str(entry.get("source_url") or "")
        source_key = path_key_from_url(source_url) if source_url.startswith("http") else source_url

        related = False
        if route_key and (route_key in api_key or api_key.endswith(route_key)):
            related = True
        if route_path and source_url:
            src_path = (urlparse(source_url).path or "").rstrip("/").lower()
            if src_path == route_path or route_path in src_path or src_path in route_path:
                related = True
        if route_key and source_key and (route_key in source_key or source_key in route_key):
            related = True
        if route_key.startswith("/api/") and route_key[4:] == api_key:
            related = True
        if api_key.startswith("/api/") and api_key[4:] == route_key:
            related = True

        if related:
            merge_into(api_key)

    return updated


async def capture_and_register_dom_fields(engine, page) -> None:
    fields = await extract_visible_form_fields(page)
    if not fields:
        return
    route_url = str(getattr(page, "url", "") or getattr(engine, "current_route_url", "") or "")
    count = register_dom_fields_for_route(engine, route_url, fields)
    if count:
        logger.debug(
            "[SPA Crawler] DOM form fields (%s keys) linked to %s API path(s) on %s",
            len(fields),
            count,
            route_url,
        )
