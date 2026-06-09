"""
SSRF 2차 검증: 저장·조회 분리형 앱(SPA API 등)에서 read-back GET으로 fetch 증거를 확인한다.

교차 오염 방지: 고유 verify probe를 재주입하고, read-back 본문에 해당 probe의
흔적이 *새로* 나타날 때만 확정한다 (다른 endpoint/이전 스캔의 SSRF 잔여물 제외).

stored_xss.verify_urls 의 후보 URL 수집 로직을 재사용하며 앱별 URL 하드코딩은 없다.
"""

from __future__ import annotations

import asyncio
import copy
from typing import Any

import aiohttp

from core.models import Payload
from fuzzer.request_builder import build_and_send_request
from modules.ssrf.analyzer import (
    build_ssrf_verify_probe,
    readback_shows_new_verify_probe,
)
from modules.ssrf.payloads import SSRFPayload
from modules.stored_xss.analyzer import (
    build_verify_request_headers,
    injection_response_implies_failed_auth,
    is_success_status,
    surface_expects_json_api,
)
from modules.stored_xss.verify_urls import (
    collect_verify_candidate_urls,
    expand_detail_urls_from_list_bodies,
    infer_list_poll_urls,
)


async def _collect_readback_urls(
    session: aiohttp.ClientSession,
    *,
    surface: Any,
    injection_res: Any,
    base_url: str,
    injection_body: str,
    max_urls: int = 12,
) -> list[str]:
    candidate_urls = collect_verify_candidate_urls(
        base_url=base_url,
        surface=surface,
        injection_res=injection_res,
        max_urls=max_urls,
    )

    req_headers = getattr(surface, "headers", {}) or {}
    req_cookies = getattr(surface, "cookies", None)
    verify_headers_base = build_verify_request_headers(surface, base_url, req_headers)
    list_bodies: list[tuple[str, str]] = []

    for list_url in infer_list_poll_urls(surface, base_url, injection_body)[:3]:
        try:
            async with session.get(
                list_url,
                headers=verify_headers_base,
                cookies=req_cookies,
                timeout=15,
            ) as list_res:
                if is_success_status(list_res.status):
                    list_bodies.append((list_url, await list_res.text()))
        except Exception:
            continue

    surface_url = str(getattr(surface, "url", "") or "")
    for detail_url in expand_detail_urls_from_list_bodies(
        list_bodies,
        base_url=base_url,
        surface=surface,
        injection_body=injection_body,
        surface_url=surface_url,
        max_items=5,
    ):
        if detail_url not in candidate_urls:
            candidate_urls.insert(0, detail_url)

    return candidate_urls


async def _fetch_readback_bodies(
    session: aiohttp.ClientSession,
    *,
    surface: Any,
    urls: list[str],
) -> dict[str, str]:
    req_headers = getattr(surface, "headers", {}) or {}
    req_cookies = getattr(surface, "cookies", None)
    bodies: dict[str, str] = {}

    for check_url in urls:
        verify_headers = build_verify_request_headers(surface, check_url, req_headers)
        try:
            async with session.get(
                check_url,
                headers=verify_headers,
                cookies=req_cookies,
                timeout=15,
            ) as verify_res:
                if is_success_status(verify_res.status):
                    bodies[check_url] = await verify_res.text()
        except Exception:
            continue
    return bodies


async def verify_ssrf_readback(
    session: aiohttp.ClientSession,
    *,
    surface: Any,
    parameter: str,
    payload: Payload,
    response: Any,
    baseline_response: Any,
) -> tuple[bool, str]:
    """
    Re-inject a unique verify probe, then confirm its SSRF side-effect appears newly
    in read-back (or inline re-inject response), not in pre-injection snapshots.
    """
    _ = payload
    _ = baseline_response

    if injection_response_implies_failed_auth(response):
        return False, ""

    verify_id, probe_port, probe_url = build_ssrf_verify_probe()
    probe_payload = SSRFPayload(
        value=probe_url,
        attack_type="verify_probe",
        risk_level="info",
    )

    target_url = str(getattr(response, "url", "") or getattr(surface, "url", "") or "")
    base_url = target_url
    injection_body = getattr(response, "text", "") or ""
    prefers_json = surface_expects_json_api(surface)

    readback_urls = await _collect_readback_urls(
        session,
        surface=surface,
        injection_res=response,
        base_url=base_url,
        injection_body=injection_body,
    )

    pre_bodies = await _fetch_readback_bodies(session, surface=surface, urls=readback_urls)

    safe_surface = copy.deepcopy(surface)
    try:
        reinject_res = await build_and_send_request(
            session,
            safe_surface,
            parameter,
            probe_payload,
        )
    except Exception:
        return False, ""

    if injection_response_implies_failed_auth(reinject_res):
        return False, ""

    await asyncio.sleep(1.0 if prefers_json else 0.75)

    reinject_body = getattr(reinject_res, "text", "") or ""
    post_urls = await _collect_readback_urls(
        session,
        surface=surface,
        injection_res=reinject_res,
        base_url=str(getattr(reinject_res, "url", "") or base_url),
        injection_body=reinject_body,
    )
    for url in readback_urls:
        if url not in post_urls:
            post_urls.append(url)

    post_bodies = await _fetch_readback_bodies(session, surface=surface, urls=post_urls)

    for check_url, post_text in post_bodies.items():
        pre_text = pre_bodies.get(check_url, "")
        if readback_shows_new_verify_probe(
            pre_text,
            post_text,
            verify_id=verify_id,
            probe_port=probe_port,
        ):
            return True, f"verify_probe={verify_id} readback at {check_url}"

    if readback_shows_new_verify_probe(
        injection_body,
        reinject_body,
        verify_id=verify_id,
        probe_port=probe_port,
    ):
        return True, f"verify_probe={verify_id} inline_reinject_response"

    return False, ""
