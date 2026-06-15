from typing import List, Optional, Any, Dict
import threading
import re
import uuid
from enum import Enum
from dataclasses import dataclass, asdict, replace
from collections import OrderedDict
import aiohttp
import asyncio

from modules.base_module import BaseModule
from core.models import Payload, AttackSurface
from modules.stored_xss.payloads import build_stored_xss_payloads, PayloadCategory, reload_payloads
from modules.stored_xss.analyzer import (
    analyze_stored_xss,
    analyze_verify_response,
    build_verify_request_headers,
    _extract_injected_marker,
    injection_response_implies_failed_auth,
    is_acceptable_verify_response,
    is_get_read_only_surface,
    is_reflected_only_param,
    is_success_status,
    slice_body_for_verify_analysis,
    surface_expects_json_api,
    surface_method_is_get,
    verify_context_matches_parameter,
    verify_implies_persistent_storage,
)
from modules.stored_xss.verify_urls import (
    collect_verify_candidate_urls,
    collect_detail_urls_from_list_response,
    infer_list_poll_urls,
)
from fuzzer.request_builder import build_and_send_request
from fuzzer.runtime_config import get_fuzzer_runtime_config


class _BoundedProgressBlocks:
    __slots__ = ("_blocks", "_max_size")

    def __init__(self, max_size: int) -> None:
        self._blocks: OrderedDict[int, None] = OrderedDict()
        self._max_size = max(1, max_size)

    def add(self, block: int) -> None:
        if block in self._blocks:
            self._blocks.move_to_end(block)
            return
        self._blocks[block] = None
        if len(self._blocks) > self._max_size:
            self._blocks.popitem(last=False)

    def __contains__(self, block: int) -> bool:
        return block in self._blocks

    def clear(self) -> None:
        self._blocks.clear()


class _BoundedLockMap:
    """Per-URL asyncio locks with LRU eviction to cap memory growth."""

    __slots__ = ("_locks", "_max_size")

    def __init__(self, max_size: int = 64) -> None:
        self._locks: OrderedDict[str, asyncio.Lock] = OrderedDict()
        self._max_size = max(1, max_size)

    def lock_for(self, key: str) -> asyncio.Lock:
        if key in self._locks:
            self._locks.move_to_end(key)
            return self._locks[key]
        lock = asyncio.Lock()
        self._locks[key] = lock
        if len(self._locks) > self._max_size:
            self._locks.popitem(last=False)
        return lock

    def clear(self) -> None:
        self._locks.clear()


def _clone_surface_for_verify(surface: Any) -> Any:
    """Shallow clone — only copies mutable request fields (no deepcopy of headers/cookies trees)."""
    if isinstance(surface, AttackSurface):
        return replace(
            surface,
            parameters=dict(surface.parameters) if surface.parameters else {},
            headers=dict(surface.headers) if surface.headers else {},
            cookies=dict(surface.cookies) if surface.cookies else {},
            dynamic_tokens=dict(surface.dynamic_tokens) if surface.dynamic_tokens else {},
        )
    cloned = replace(surface) if hasattr(surface, "__dataclass_fields__") else surface
    for attr in ("parameters", "headers", "cookies", "dynamic_tokens"):
        value = getattr(cloned, attr, None)
        if isinstance(value, dict):
            setattr(cloned, attr, dict(value))
    return cloned


def _stored_xss_runtime():
    return get_fuzzer_runtime_config().stored_xss


class ScanMode(Enum):
    QUICK = "quick"
    FULL = "full"
    STEALTH = "stealth"


@dataclass
class ScanStats:
    total_payloads: int = 0
    tested: int = 0
    vulnerable: int = 0
    waf_blocked: int = 0
    dom_potential: int = 0


class StoredXSSModule(BaseModule):
    def __init__(
            self,
            target_params: list = None,
            bypass_level: int = 1,
            scan_mode: str = "full",
            max_risk_level: str = "Critical",
            categories: list = None
    ):
        super().__init__(name="stored_xss")
        self.description = "Advanced Stored XSS Scanner (Micro-Batch Verification)"
        self.version = "4.0.0"

        self.target_params = target_params or []
        self.bypass_level = bypass_level
        self.scan_mode = ScanMode(scan_mode)
        self.max_risk_level = max_risk_level
        self.categories = categories or []
        self.config = {
            "target_params": self.target_params,
            "bypass_level": self.bypass_level,
            "scan_mode": self.scan_mode.value,
            "max_risk_level": self.max_risk_level,
            "categories": self.categories
        }
        self._baseline_response: Optional[str] = None
        self.stats = ScanStats()
        self._last_analysis_result: Optional[Dict[str, Any]] = None
        self._stats_lock = threading.Lock()  # 동기 함수용
        self._async_stats_lock = asyncio.Lock()  # 비동기 함수(verify)용
        self._cached_payloads: Optional[List[Payload]] = None

        sx_cfg = _stored_xss_runtime()
        self._target_locks = _BoundedLockMap(max_size=sx_cfg.lock_map_size)
        self._verify_semaphore = asyncio.Semaphore(max(1, sx_cfg.verify_concurrency))
        self._logged_progress_blocks = _BoundedProgressBlocks(sx_cfg.progress_log_blocks_max)

    def reset_stats(self) -> None:
        with self._stats_lock:
            self.stats = ScanStats()
            self._last_analysis_result = None
            self._logged_progress_blocks.clear()
            self._target_locks.clear()
            self._cached_payloads = None

    def set_baseline(self, response: Any) -> None:
        if response and hasattr(response, 'text') and response.text:
            self._baseline_response = response.text

    def reload_database(self) -> None:
        reload_payloads()

    def get_target_parameters(self, surface, parameters: List[str]) -> List[str]:
        # 저장형 XSS는 데이터 변경 엔드포인트(POST 등)가 대상. GET 목록·상세 조회는 반사형 영역.
        if surface_method_is_get(surface):
            return []

        destructive_keys = {"btnclear", "clear", "reset", "delete", "destroy", "remove"}

        if hasattr(surface, 'parameters') and isinstance(surface.parameters, dict):
            keys_to_remove = [k for k in surface.parameters.keys() if str(k).lower() in destructive_keys]
            for k in keys_to_remove:
                del surface.parameters[k]

            for key, value in surface.parameters.items():
                if value == "" or value is None:
                    key_lower = str(key).lower()
                    skip_dummy = {"submit", "action", "login", "logout", "cancel", "update", "btnsign", "button"}
                    number_hints = {"price", "id", "amount", "qty", "count", "num", "book_id"}

                    if key_lower in skip_dummy:
                        surface.parameters[key] = "Submit"
                    elif any(hint in key_lower for hint in number_hints):
                        surface.parameters[key] = "1"  # 숫자 타입 검증 회피 (400 에러 방지)
                    else:
                        surface.parameters[key] = "test"

        valid_targets = []

        skip_keys = {
            "submit", "action", "login", "logout", "cancel", "update", "btnsign", "search", "page",
            "lang", "theme", "csrf_token", "user_token", "_token", "authenticity_token",
            "keyword", "q", "query", "term", "searchtext",
        }.union(destructive_keys)

        if self.target_params:
            for p in parameters:
                if p in self.target_params and str(p).lower() not in skip_keys:
                    if is_get_read_only_surface(surface, p) or is_reflected_only_param(p):
                        continue
                    valid_targets.append(p)
            return valid_targets

        for p in parameters:
            if str(p).lower() not in skip_keys:
                if is_get_read_only_surface(surface, p) or is_reflected_only_param(p):
                    continue
                valid_targets.append(p)

        return valid_targets

    def get_payloads(self) -> List[Payload]:
        if self._cached_payloads is not None:
            return self._cached_payloads
        try:
            categories = [PayloadCategory.BASIC,
                          PayloadCategory.EVENT_HANDLER] if self.scan_mode == ScanMode.QUICK else None
            if not categories:
                raw_cats = self.categories
                categories = [PayloadCategory(c) for c in raw_cats] if raw_cats else None

            payloads = build_stored_xss_payloads(
                categories=categories,
                max_risk_level=self.max_risk_level,
                mutation_level=self.bypass_level
            )
            with self._stats_lock:
                self.stats.total_payloads = len(payloads)
            self._cached_payloads = payloads
            return payloads
        except ValueError:
            self._cached_payloads = []
            return []

    def get_payload_count(self) -> int:
        # Must match get_payloads() (mutation_level, categories, risk filter).
        return len(self.get_payloads())

    def analyze(
            self,
            response: Any,
            payload: Payload,
            elapsed_time: float,
            original_res: Any = None,
            requester: Any = None,
            surface: Any = None,
    ) -> bool:
        with self._stats_lock:
            self.stats.tested += 1
        try:
            baseline_text = self._baseline_response
            if not baseline_text and original_res and hasattr(original_res, 'text'):
                baseline_text = original_res.text

            result = analyze_stored_xss(
                response,
                payload,
                elapsed_time,
                None if baseline_text else original_res,
                requester,
                baseline_text,
                surface=surface,
            )
            self._last_analysis_result = result
            is_hit = bool(result.get("is_vulnerable", False))

            with self._stats_lock:
                if is_hit:
                    if result.get("waf_blocked"):
                        self.stats.waf_blocked += 1
                    if result.get("needs_manual_dom_review"):
                        self.stats.dom_potential += 1
            return is_hit
        except Exception as e:
            self._last_analysis_result = {
                "is_vulnerable": False,
                "context": "error",
                "evidence": f"Analysis failed: {str(e)}",
            }
            return False

    async def verify(self, session: aiohttp.ClientSession, surface: Any, parameter: str, payload: Payload,
                     response: Any, baseline_response: Any) -> bool:
        """
        2차 주입 마커를 넣은 뒤, 수집한 후보 URL들을 GET하여 저장·실행 여부를 확인한다.
        후보 URL은 verify_urls.collect_verify_candidate_urls (앱별 하드코딩 없음)로 수집한다.
        """
        try:
            async with self._verify_semaphore:
                return await self._run_verify(
                    session, surface, parameter, payload, response, baseline_response
                )
        except Exception:
            return False

    async def _run_verify(
        self,
        session: aiohttp.ClientSession,
        surface: Any,
        parameter: str,
        payload: Payload,
        response: Any,
        baseline_response: Any,
    ) -> bool:
        try:
            payload_value = payload.value or ""
            original_marker = _extract_injected_marker(payload_value)
            if not original_marker:
                return False

            safe_surface = _clone_surface_for_verify(surface)
            safe_param_name = re.sub(r'[^a-zA-Z0-9_]', '', parameter)
            verify_id = uuid.uuid4().hex[:6]
            verify_marker = f"vfy_{safe_param_name}_{verify_id}"
            verify_payload_value = payload_value.replace(original_marker, verify_marker)

            class MockPayload:
                def __init__(self, val):
                    self.value = val

            target_url = str(response.url) if hasattr(response, 'url') else getattr(surface, 'url', '')
            base_url = target_url

            # 1. 고유 마커 2차 주입 (POST)
            injection_res = await build_and_send_request(
                session, safe_surface, parameter, MockPayload(verify_payload_value)
            )

            if injection_response_implies_failed_auth(injection_res):
                return False

            req_headers = getattr(surface, "headers", {}) or {}
            prefers_json = surface_expects_json_api(safe_surface)
            sx_cfg = _stored_xss_runtime()

            candidate_urls = collect_verify_candidate_urls(
                base_url=base_url,
                surface=safe_surface,
                injection_res=injection_res,
                max_urls=sx_cfg.verify_max_urls,
            )

            await asyncio.sleep(1.0 if prefers_json else 0.75)

            injection_body = getattr(injection_res, "text", "") or ""
            list_poll_urls = (
                infer_list_poll_urls(safe_surface, base_url, injection_body)
                if prefers_json
                else []
            )
            verify_headers_base = build_verify_request_headers(
                safe_surface, base_url, req_headers
            )
            seen_detail_urls: set[str] = set()
            # 목록 URL이 후보에 이미 있어도 id→view URL 생성을 위해 반드시 fetch한다.
            for list_url in list_poll_urls[: sx_cfg.list_poll_max]:
                try:
                    async with session.get(
                        list_url,
                        headers=verify_headers_base,
                        cookies=getattr(surface, "cookies", None),
                        timeout=15,
                    ) as list_res:
                        if not is_success_status(list_res.status):
                            continue
                        list_text = await list_res.text(errors="replace")
                        for detail_url in collect_detail_urls_from_list_response(
                            list_text,
                            base_url=base_url,
                            surface=safe_surface,
                            injection_body=injection_body,
                            surface_url=str(getattr(safe_surface, "url", "") or ""),
                            max_items=sx_cfg.verify_detail_max_items,
                        ):
                            if detail_url not in seen_detail_urls:
                                seen_detail_urls.add(detail_url)
                                if detail_url not in candidate_urls:
                                    candidate_urls.insert(0, detail_url)
                except Exception:
                    continue

            is_vulnerable = False
            verified_location = ""
            hit_url = ""

            for check_url in candidate_urls:
                verify_body = ""
                verify_status = 0
                verify_response_headers: dict[str, str] = {}
                verify_headers = build_verify_request_headers(
                    safe_surface, check_url, req_headers
                )
                async with self._target_locks.lock_for(check_url):
                    try:
                        req_cookies = getattr(surface, 'cookies', None)
                        async with session.get(
                            check_url,
                            headers=verify_headers,
                            cookies=req_cookies,
                            timeout=15,
                        ) as verify_res:
                            verify_status = verify_res.status
                            if not is_success_status(verify_status):
                                continue
                            verify_body = await verify_res.text(errors="replace")
                            verify_response_headers = {
                                str(k): str(v) for k, v in verify_res.headers.items()
                            }
                    except Exception:
                        continue

                if not is_acceptable_verify_response(
                    verify_status, verify_body, marker=verify_marker
                ):
                    continue

                if verify_marker not in verify_body:
                    continue

                analysis_body = slice_body_for_verify_analysis(
                    verify_body,
                    verify_marker,
                    headers=verify_response_headers,
                )
                context_state = analyze_verify_response(
                    analysis_body,
                    verify_marker,
                    verify_marker,
                    headers=verify_response_headers,
                )

                if context_state.get("executable"):
                    if not verify_context_matches_parameter(
                        parameter, context_state.get("location", "")
                    ):
                        continue
                    if not verify_implies_persistent_storage(
                        safe_surface, target_url, check_url
                    ):
                        continue
                    is_vulnerable = True
                    verified_location = context_state.get('location', 'unknown_location')
                    hit_url = check_url
                    break

            if is_vulnerable:
                current_tested = self.stats.tested
                progress_block = current_tested // 10

                if progress_block not in self._logged_progress_blocks:
                    self._logged_progress_blocks.add(progress_block)

                if self._last_analysis_result:
                    self._last_analysis_result["context"] = f"Verified Stored | {verified_location}"
                    self._last_analysis_result[
                        "evidence"] = f"Re-injection success with marker: {verify_marker} at {hit_url}"

                await self._async_record_verified_stats()

            return is_vulnerable

        except Exception:
            return False

    def _record_verified_stats(self):
        with self._stats_lock:
            self.stats.vulnerable += 1

    async def _async_record_verified_stats(self):
        async with self._async_stats_lock:
            self.stats.vulnerable += 1

    def get_last_analysis_result(self) -> Optional[Dict[str, Any]]:
        return self._last_analysis_result

    def get_module_info(self) -> dict:
        with self._stats_lock:
            stats_copy = asdict(self.stats)
        return {
            "name": self.name,
            "version": self.version,
            "mode": self.scan_mode.value,
            "stats": stats_copy,
            "config": self.config
        }