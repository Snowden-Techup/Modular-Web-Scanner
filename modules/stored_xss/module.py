from typing import List, Optional, Any, Dict
import threading
import re
import uuid
from enum import Enum
from dataclasses import dataclass, asdict
import aiohttp
import copy
import asyncio

from modules.base_module import BaseModule
from core.models import Payload
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
    surface_expects_json_api,
    surface_method_is_get,
    verify_context_matches_parameter,
    verify_implies_persistent_storage,
)
from modules.stored_xss.verify_urls import (
    collect_verify_candidate_urls,
    expand_detail_urls_from_list_bodies,
    infer_list_poll_urls,
)
from fuzzer.request_builder import build_and_send_request


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

        #  묶음 검증(배치)을 위한 캐시 및 Lock 변수
        self._target_locks: Dict[str, asyncio.Lock] = {}
        self._html_cache: Dict[str, Dict[str, Any]] = {}
        self._logged_progress_blocks: set = set()

    def reset_stats(self) -> None:
        with self._stats_lock:
            self.stats = ScanStats()
            self._last_analysis_result = None
            self._logged_progress_blocks.clear()
            self._html_cache.clear()
            self._target_locks.clear()

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
            return payloads
        except ValueError:
            return []

    def get_payload_count(self) -> int:
        from modules.stored_xss.payloads import get_payload_count as get_db_count
        counts = get_db_count()
        if self.scan_mode == ScanMode.QUICK:
            return counts.get("basic", 0) + counts.get("event_handler", 0)
        raw_cats = self.categories
        if raw_cats:
            return sum(counts.get(c, 0) for c in raw_cats)
        return sum(counts.values())

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
                original_res,
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
            payload_value = payload.value or ""
            original_marker = _extract_injected_marker(payload_value)
            if not original_marker:
                return False

            safe_surface = copy.deepcopy(surface)
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
            candidate_urls = collect_verify_candidate_urls(
                base_url=base_url,
                surface=safe_surface,
                injection_res=injection_res,
                max_urls=8,
            )

            await asyncio.sleep(1.0 if prefers_json else 0.75)

            injection_body = getattr(injection_res, "text", "") or ""
            list_poll_urls = (
                infer_list_poll_urls(safe_surface, base_url, injection_body)
                if prefers_json
                else []
            )
            list_bodies: list[tuple[str, str]] = []
            verify_headers_base = build_verify_request_headers(
                safe_surface, base_url, req_headers
            )
            # 목록 URL이 후보에 이미 있어도 id→view URL 생성을 위해 반드시 fetch한다.
            for list_url in list_poll_urls[:3]:
                try:
                    async with session.get(
                        list_url,
                        headers=verify_headers_base,
                        cookies=getattr(surface, "cookies", None),
                        timeout=15,
                    ) as list_res:
                        if is_success_status(list_res.status):
                            list_bodies.append((list_url, await list_res.text()))
                except Exception:
                    continue
            for detail_url in expand_detail_urls_from_list_bodies(
                list_bodies,
                base_url=base_url,
                surface=safe_surface,
                injection_body=injection_body,
                surface_url=str(getattr(safe_surface, "url", "") or ""),
                max_items=4,
            ):
                if detail_url not in candidate_urls:
                    candidate_urls.insert(0, detail_url)

            is_vulnerable = False
            verified_location = ""
            hit_url = ""
            fetch_cache: Dict[str, Dict[str, Any]] = {}

            for check_url in candidate_urls:
                if check_url not in self._target_locks:
                    self._target_locks[check_url] = asyncio.Lock()

                verify_body = ""
                verify_status = 0
                verify_response_headers: dict[str, str] = {}
                verify_headers = build_verify_request_headers(
                    safe_surface, check_url, req_headers
                )
                async with self._target_locks[check_url]:
                    cached = fetch_cache.get(check_url)
                    if cached is not None:
                        verify_status = cached.get("status", 0)
                        verify_body = cached.get("body", "")
                        verify_response_headers = cached.get("headers", {})
                    else:
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
                                verify_body = await verify_res.text()
                                verify_response_headers = {
                                    str(k): str(v) for k, v in verify_res.headers.items()
                                }
                                fetch_cache[check_url] = {
                                    "status": verify_status,
                                    "body": verify_body,
                                    "headers": verify_response_headers,
                                }
                        except Exception:
                            continue

                if not is_acceptable_verify_response(
                    verify_status, verify_body, marker=verify_marker
                ):
                    continue

                if verify_marker not in verify_body:
                    continue

                context_state = analyze_verify_response(
                    verify_body,
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