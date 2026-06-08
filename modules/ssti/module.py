from __future__ import annotations

import asyncio
import atexit
import dataclasses
import logging
import random
import re
from collections import OrderedDict
from concurrent.futures import ProcessPoolExecutor
from typing import Any, List, Tuple
from urllib.parse import parse_qs, urlparse

from core.models import Payload
from modules.base_module import BaseModule
from modules.ssti.analyzer import Confidence, SSTIResult, detect_ssti
from modules.ssti.payloads import get_ssti_payloads

logger = logging.getLogger(__name__)

# ============================================================
# ProcessPoolExecutor (CPU-bound analyzer 격리)
# ============================================================
_executor: ProcessPoolExecutor | None = None


def _get_executor() -> ProcessPoolExecutor:
    global _executor
    if _executor is None:
        _executor = ProcessPoolExecutor(max_workers=4)
        atexit.register(_executor.shutdown, wait=False)
    return _executor


# ============================================================
# OOM 방지: LRU Dedup 캐시
# ============================================================
_DEDUP_MAX_ENTRIES = 10_000


class _LRUSet:
    """OrderedDict 기반 LRU Set. 10K 초과 시 가장 오래된 키부터 evict."""

    __slots__ = ("_data", "_max")

    def __init__(self, max_size: int = _DEDUP_MAX_ENTRIES):
        self._data: OrderedDict[Tuple[Any, ...], None] = OrderedDict()
        self._max = max_size

    def __contains__(self, key: Tuple[Any, ...]) -> bool:
        if key in self._data:
            self._data.move_to_end(key)
            return True
        return False

    def add(self, key: Tuple[Any, ...]) -> None:
        if key in self._data:
            self._data.move_to_end(key)
            return
        self._data[key] = None
        if len(self._data) > self._max:
            self._data.popitem(last=False)


def _engine_from_attack_type(attack_type: str) -> str:
    """`ssti:<engine>`에서 엔진명만 추출 (dedup/리포트 보조용)."""
    parts = str(attack_type or "").split(":")
    if len(parts) >= 2 and parts[1]:
        return parts[1].lower()
    return "unknown"


_DEBUG_PAGE_SIGNATURES = (
    re.compile(r"Werkzeug Debugger", re.IGNORECASE),
    re.compile(r"Whitelabel Error Page", re.IGNORECASE),
    re.compile(r"Whoops\s*There was an error", re.IGNORECASE),
    re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"Exception Value:", re.IGNORECASE),
    re.compile(r"Ignition", re.IGNORECASE),
)


def _is_debug_error_page(res_text: str) -> bool:
    """200 OK이어도 SSTI/템플릿 에러가 드러나는 디버그·에러 페이지 여부."""
    if not res_text:
        return False
    return any(sig.search(res_text) for sig in _DEBUG_PAGE_SIGNATURES)


# ============================================================
# SSTI Module
# ============================================================
class SSTIModule(BaseModule):
    """Server-Side Template Injection 탐지 모듈 (Option A: 1:N expected_map)."""

    _MAX_RESPONSE_SIZE = 5 * 1024 * 1024

    _ALLOWED_CONTENT_TYPES = (
        "text/html",
        "application/xhtml",
        "text/plain",
        "application/json",
        "text/xml",
        "application/xml",
    )

    def __init__(self, **kwargs):
        super().__init__("ssti")
        self.max_response_size: int = kwargs.get(
            "max_response_size", self._MAX_RESPONSE_SIZE
        )

        raw_level = kwargs.get("evasion_level", 0)
        self.evasion_level: int = max(0, min(3, int(raw_level)))

        self.max_payloads: int | None = kwargs.get("max_payloads", None)

        self.reported_findings: _LRUSet = _LRUSet(_DEDUP_MAX_ENTRIES)
        self._seen_surfaces: set[Tuple[str, str, str]] = set()

        payloads_list, expected_map = get_ssti_payloads(evasion_level=self.evasion_level)
        # 호출자 변형과 분리: expected_map은 value 키 기준 shallow copy
        self._expected_map: dict[str, list[str]] = {
            value: list(expecteds) for value, expecteds in expected_map.items()
        }
        self._cached_payloads: List[Payload] = self._get_sampled_payloads(payloads_list)

    # --------------------------------------------------------
    # Payload provisioning
    # --------------------------------------------------------
    def _get_sampled_payloads(self, all_payloads: List[Payload]) -> List[Payload]:
        if self.max_payloads is None or len(all_payloads) <= self.max_payloads:
            return list(all_payloads)

        high = [p for p in all_payloads if getattr(p, "risk_level", "") == "HIGH"]
        others = [p for p in all_payloads if getattr(p, "risk_level", "") != "HIGH"]

        if len(high) >= self.max_payloads:
            sampled = random.sample(high, self.max_payloads)
        else:
            remaining = self.max_payloads - len(high)
            sampled = high + random.sample(others, min(remaining, len(others)))

        logger.info(
            f"[SSTI] 페이로드 샘플링: {len(all_payloads)} → {len(sampled)}개 "
            f"(max_payloads={self.max_payloads})"
        )
        return sampled

    def get_payloads(self) -> List[Payload]:
        return self._cached_payloads

    def get_payload_count(self) -> int:
        return len(self._cached_payloads)

    # --------------------------------------------------------
    # Main analyze
    # --------------------------------------------------------
    async def analyze(
        self,
        response: Any,
        payload: Any,
        elapsed_time: float,
        original_res: Any = None,
        requester: Any = None,
    ):
        """
        SSTI 취약점 분석.

        네트워크 요청 1회당 동일 응답에 대해 expected_map의 N개 expected를 순차 검증한다.
        """
        FAIL: Tuple[bool, List[str], Any] = (False, [], payload)
        
        
        try:
            content_type = str(
                getattr(response, "content_type", "")
                or getattr(response, "headers", {}).get("content-type", "")
            ).lower()

            if content_type and not any(
                ct in content_type for ct in self._ALLOWED_CONTENT_TYPES
            ):
                return FAIL

            req_url = ""
            if requester and hasattr(requester, "url"):
                req_url = str(requester.url)
            else:
                req_url = str(getattr(response, "url", ""))

            target_parameter = self._extract_parameter(requester, response)
            if target_parameter == "unknown" and req_url:
                target_parameter = self._smart_recover_parameter(req_url, payload)

            res_text = getattr(response, "text", None)
            if not res_text:
                return FAIL

            if len(res_text) > self.max_response_size:
                res_text = res_text[: self.max_response_size]

            orig_text = ""
            if original_res:
                orig_text = getattr(original_res, "text", "") or ""
                if len(orig_text) > self.max_response_size:
                    orig_text = orig_text[: self.max_response_size]

            payload_value = getattr(payload, "value", str(payload))
            attack_type = getattr(payload, "attack_type", "") or ""

            expected_candidates = self._expected_map.get(payload_value, [])
            if not expected_candidates:
                logger.debug(
                    f"[SSTI] no expected candidates for payload value "
                    f"(attack_type='{attack_type}')"
                )
                return FAIL

            status_code = int(
                getattr(response, "status", getattr(response, "status_code", 200))
                or 200
            )

            loop = asyncio.get_running_loop()

            # 1:N 매핑: 동일 응답에 대해 expected별로 analyzer 호출 (재요청 없음)
            for expected_result in expected_candidates:
                try:
                    result = await loop.run_in_executor(
                        _get_executor(),
                        detect_ssti,
                        res_text,
                        orig_text,
                        payload_value,
                        attack_type,
                        expected_result,
                    )
                except Exception as exc:
                    logger.error(
                        f"[SSTI] detect_ssti executor failed: {exc}", exc_info=True
                    )
                    continue

                if not isinstance(result, SSTIResult):
                    continue
                

                signals = result.signals if isinstance(result.signals, dict) else {}
                self._log_analyzer_signals(req_url, target_parameter, signals)

                # baseline에만 존재하는 expected → 다른 expected로 재시도
                if signals.get("requires_reverification"):
                    continue

                if not result.is_vulnerable or result.confidence == Confidence.NONE:
                    continue

                hit = self._finalize_hit(
                    result=result,
                    payload=payload,
                    attack_type=attack_type,
                    expected_result=expected_result,
                    status_code=status_code,
                    res_text=res_text,
                    req_url=req_url,
                    target_parameter=target_parameter,
                )
                if hit is not None:
                    return hit

            return FAIL

        except Exception as exc:
            logger.error(f"[SSTI] 분석 중 오류: {exc}", exc_info=True)
            return (False, [], payload)

    def _finalize_hit(
        self,
        result: SSTIResult,
        payload: Any,
        attack_type: str,
        expected_result: str,
        status_code: int,
        res_text: str,
        req_url: str,
        target_parameter: str,
    ) -> Tuple[bool, List[str], Any] | None:
        """
        analyzer 히트를 상태코드 튜닝·dedup·리포트 튜플로 변환.
        드랍 시 None 반환(다음 expected 시도 가능).
        """
        confidence = result.confidence
        evidence_text = str(result.evidence or "")
        is_error_based = bool(result.is_error_based)
        debug_page_200 = False

        # 에러 기반 + 200: 디버그 페이지는 유지, 그 외는 신뢰도만 격하
        if is_error_based and status_code == 200:
            if _is_debug_error_page(res_text):
                debug_page_200 = True
                evidence_text = f"[Debug Page 200 OK] {evidence_text}"
            else:
                if confidence == Confidence.HIGH:
                    confidence = Confidence.MEDIUM
                elif confidence == Confidence.MEDIUM:
                    confidence = Confidence.LOW
                evidence_text = f"[200 OK Suspicious] {evidence_text}"
                if confidence == Confidence.LOW:
                    logger.debug(
                        f"[SSTI] error-based downgraded to LOW (200 OK) "
                        f"expected='{expected_result}'"
                    )
                    return None

        if status_code >= 500 and is_error_based:
            if confidence == Confidence.MEDIUM:
                confidence = Confidence.HIGH
                evidence_text = f"[5xx Upgraded] {evidence_text}"
            elif confidence == Confidence.LOW:
                confidence = Confidence.MEDIUM
                evidence_text = f"[5xx Upgraded] {evidence_text}"
        elif status_code in (403, 406):
            if confidence == Confidence.HIGH:
                confidence = Confidence.MEDIUM
            evidence_text = f"[WAF/Filter {status_code}] {evidence_text}"
        elif status_code in (400, 404):
            if confidence == Confidence.HIGH:
                confidence = Confidence.MEDIUM
            evidence_text = f"[{status_code} Error] {evidence_text}"

        if confidence == Confidence.LOW and not debug_page_200:
            return None

        engine = str(result.engine or _engine_from_attack_type(attack_type))

        raw_url = str(req_url)
        parsed = urlparse(raw_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # dedup 키에 페이로드 값 포함 → 변형 페이로드도 별건으로 보고
        dedup_key: Tuple[str, str, str, str] = (
            base_url,
            str(target_parameter),
            engine,
            str(getattr(payload, "value", "")),
        )
        if dedup_key in self.reported_findings:
            return None

        self.reported_findings.add(dedup_key)

        # surface(URL+param+engine) 단위 첫 hit 여부 추적
        surface_key = (base_url, str(target_parameter), engine)
        is_evasion_hit = surface_key in self._seen_surfaces
        self._seen_surfaces.add(surface_key)

        final_risk = confidence.name
        if final_risk != getattr(payload, "risk_level", ""):
            try:
                payload = dataclasses.replace(payload, risk_level=final_risk)
            except Exception as exc:
                logger.debug(f"[SSTI] payload replace failed: {exc}")

        evidences: List[str] = [
            f"Confidence: {confidence.name}",
            f"Engine: {engine}",
            f"AttackType: {attack_type}",
            f"Expected: {expected_result}",
            f"Evidence: {evidence_text}",
            f"Status: {status_code}",
        ]

        # 변형 페이로드로 잡힌 경우 evasion 성공 표기
        if is_evasion_hit:
            evidences.append("Variant: Mutated payload bypassed (evasion candidate)")

        signals = result.signals if isinstance(result.signals, dict) else {}
        if signals:
            signal_summary = ", ".join(f"{k}={v}" for k, v in signals.items() if v)
            if signal_summary:
                evidences.append(f"Signals: {signal_summary}")

        return (True, evidences, payload)

    def _log_analyzer_signals(
        self, req_url: str, target_parameter: str, signals: dict
    ) -> None:
        if signals.get("cross_module_signal"):
            logger.debug(
                f"[SSTI][signal] cross_module_signal on {req_url} "
                f"param={target_parameter} hint={signals.get('cross_module_signal')}"
            )
        if signals.get("baseline_match_no_delta"):
            logger.debug(
                f"[SSTI][signal] baseline_match_no_delta on {req_url} "
                f"param={target_parameter}"
            )
        if signals.get("chained_engines_detected"):
            logger.debug(
                f"[SSTI][signal] chained_engines_detected="
                f"{signals['chained_engines_detected']} on {req_url} "
                f"param={target_parameter}"
            )

    # --------------------------------------------------------
    # Parameter recovery helpers
    # --------------------------------------------------------
    def _smart_recover_parameter(self, url: str, payload: Any) -> str:
        """URL 쿼리/패스에서 페이로드가 주입된 파라미터를 역추적."""
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)

            raw_payload = (
                payload
                if isinstance(payload, str)
                else getattr(payload, "value", str(payload))
            )
            raw_payload = str(raw_payload or "")

            if not raw_payload or len(raw_payload) < 4:
                return "unknown"

            if query_params:
                for key, values in query_params.items():
                    for val in values:
                        if raw_payload == val:
                            return key
                for key, values in query_params.items():
                    for val in values:
                        if raw_payload in (val or ""):
                            return key

            if raw_payload in (parsed_url.path or ""):
                segments = parsed_url.path.strip("/").split("/")
                for idx, seg in enumerate(segments):
                    if raw_payload in seg:
                        return f"url_path[{idx}]"
                return "url_path"

            if query_params:
                first_param = next(iter(query_params.keys()))
                logger.debug(
                    f"[SSTI] 파라미터 특정 불가 — '{first_param}' 추정 사용 (격리됨)"
                )
                return f"__guess__:{first_param}"

            return "unknown"

        except Exception as exc:
            logger.debug(f"[SSTI] smart_recover_parameter failed: {exc}")
            return "unknown"

    def _extract_parameter(self, requester: Any, response: Any) -> str:
        """Requester 메타에서 파라미터명 추출."""
        if requester is not None:
            if hasattr(requester, "current_param") and requester.current_param:
                return str(requester.current_param)
            if hasattr(requester, "parameter") and requester.parameter:
                return str(requester.parameter)
            if hasattr(requester, "meta"):
                meta = requester.meta
                if isinstance(meta, dict):
                    param = meta.get("parameter") or meta.get("param")
                    if param:
                        return str(param)
                else:
                    param = getattr(meta, "parameter", None) or getattr(
                        meta, "param", None
                    )
                    if param:
                        return str(param)
        return "unknown"


__all__ = ("SSTIModule",)