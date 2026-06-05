from __future__ import annotations

import re
import html as _html
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FP 위험도 분류 임계값 (Phase 2: 설정 파일 또는 랜덤 페이로드로 이전)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MIN_NUMERIC_EXPECTED_LEN = 5
MIN_SPECIAL_EXPECTED_LEN = 6
MIN_GENERIC_EXPECTED_LEN = 8
SPECIAL_CHARS_FOR_SAFETY = "<>{}[]()/\\:;\"'"


# ============================================================
# Enum & DataClass
# ============================================================
class Confidence(Enum):
    NONE = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4


@dataclass
class SSTIResult:
    """
    SSTI 분석 결과 컨테이너
    
    [signals Schema]
    - baseline_missing (bool): 원본 정상 응답 부재
    - is_reflected (bool): 페이로드가 응답에 단순 반사됨
    - result_count_delta (int): 연산 결과값 출현 증가량
    - error_count_delta (int): 에러 시그니처 출현 증가량
    - payload_reflection_count (int): 페이로드 원본 반사 횟수
    - baseline_match_no_delta (bool): 결과값이 원래 페이지에 존재, 증가하지 않음
    - engine_mismatch_dropped (bool): 노이즈 차단을 위해 불일치 에러를 버림
    - chained_engines_detected (dict): 화이트리스트 기반 체이닝 엔진 감지
    - unknown_engine_match (bool): 선언 엔진이 없는 상태에서 에러 매칭됨
    - cross_module_signal (dict): mismatch로 차단된 에러의 cross-module 단서
    - requires_reverification (bool): module.py 측 재검증 필요 신호
    """
    is_vulnerable: bool
    confidence: Confidence
    engine: str
    evidence: str = ""
    is_error_based: bool = False
    signals: dict = field(default_factory=dict)


@dataclass
class ErrorMatch:
    engine: str
    err_str: str
    orig_count: int
    res_count: int
    score: int


# ============================================================
# 엔진 에러 시그니처 (Priority Scoring)
# ============================================================
ENGINE_ERRORS = {
    "jinja2": [(r"jinja2\.exceptions\.\w+", 10), (r"TemplateSyntaxError", 5), (r"UndefinedError", 5), (r"jinja2\.runtime", 8)],
    "twig": [(r"Twig\\Error", 10), (r"Twig_Error", 10)],
    "freemarker": [(r"freemarker\.template", 10), (r"freemarker\.core", 8), (r"FreeMarker template error", 10)],
    "erb": [(r"ActionView::Template::Error", 10), (r"ERB::", 10), (r"\(erb\):\d+", 8)],
    "velocity": [(r"org\.apache\.velocity", 10), (r"VelocityException", 8), (r"ParseErrorException", 5)],
    "smarty": [(r"SmartyCompilerException", 10), (r"Smarty_Internal", 8), (r"Smarty error", 5)],
    "spel": [(r"org\.springframework\.expression", 8), (r"SpelEvaluationException", 10)],
    "ognl": [
        (r"ognl\.OgnlException", 10),
        (r"ognl\.ExpressionSyntaxException", 10),
        (r"org\.apache\.struts2", 8),
        (r"com\.opensymphony\.xwork", 8),
    ],
    "thymeleaf": [(r"org\.thymeleaf\.exceptions", 10), (r"TemplateProcessingException", 8)],
    "mako": [(r"mako\.exceptions", 10), (r"mako\.runtime", 8)],
    "tornado": [(r"tornado\.template", 10)],
    "pebble": [(r"com\.mitchellbosecke\.pebble", 10)],
    "razor": [(r"RazorEngine", 10), (r"Microsoft\.AspNetCore\.Razor", 8)],
}

_COMPILED_ENGINE_ERRORS = {
    engine: [(re.compile(p, re.IGNORECASE), weight) for p, weight in patterns]
    for engine, patterns in ENGINE_ERRORS.items()
}

# 체이닝 엔진 화이트리스트
CHAINED_ENGINES = {
    ("thymeleaf", "spel"),
    ("thymeleaf", "ognl"),
}


# ============================================================
# 내부 유틸리티 함수
# ============================================================
def _get_result_pattern(expected_result: str) -> re.Pattern:
    safe_res = re.escape(expected_result)
    return re.compile(rf'(?<!\w){safe_res}(?!\w)')


def _is_engine_compatible(declared: str, detected: str) -> bool:
    if declared == detected:
        return True
    if declared == "jinja2_twig" and detected in ("jinja2", "twig"):
        return True
    return False


def _is_engine_chained(declared: str, detected: str) -> bool:
    """
    체이닝 엔진 호환성 검증.
    Thymeleaf(외부)가 SpEL/OGNL(내부)을 wrapping하는 단방향만 허용.
    """
    return (declared, detected) in CHAINED_ENGINES


def _identify_engine(payload: str, attack_type: str) -> str:
    """
    Declared Engine을 최우선으로 신뢰.
    Fallback에서는 단일 엔진 고유 시그니처만 인정하고,
    다중 엔진 공유 syntax(${...}, <%)는 unknown 유지.
    """
    parts = attack_type.split(':')
    declared = parts[1].lower() if len(parts) >= 2 and parts[1] else "unknown"

    if declared in ENGINE_ERRORS or declared == "jinja2_twig":
        return declared

    if 'T(java.lang' in payload or '#{T(' in payload:
        return "spel"
    if '#set' in payload or '#if' in payload:
        return "velocity"
    if '{{' in payload and '}}' in payload:
        return "jinja2_twig"

    return declared


def _is_payload_reflected(res_text: str, payload: str) -> bool:
    if not payload or not res_text:
        return False
    return payload in res_text

def _is_payload_reflected(res_text: str, payload: str) -> bool:
    if not payload or not res_text:
        return False
    return payload in res_text


def _is_expected_too_risky(expected: str) -> bool:
    """expected가 우연 매칭 위험이 높은지 판단 (엔트로피 기반)."""
    if not expected:
        return True
    if expected.isdigit() and len(expected) >= MIN_NUMERIC_EXPECTED_LEN:
        return False
    has_special = any(c in expected for c in SPECIAL_CHARS_FOR_SAFETY)
    if has_special and len(expected) >= MIN_SPECIAL_EXPECTED_LEN:
        return False
    return len(expected) < MIN_GENERIC_EXPECTED_LEN


def _normalize_response(text: str) -> str:
    """응답 텍스트를 HTML 엔티티 1차 디코딩."""
    if not text or "&" not in text:
        return text
    try:
        decoded = _html.unescape(text)
        return decoded if decoded != text else text
    except Exception as exc:
        logger.debug(f"[SSTI] HTML unescape failed: {exc}")
        return text


def _check_expected_in_response(res_text: str, check_pattern: re.Pattern) -> int:
    """응답에서 expected 패턴 등장 횟수 (HTML 디코딩 포함)."""
    direct_count = len(check_pattern.findall(res_text))
    if direct_count > 0:
        return direct_count
    normalized = _normalize_response(res_text)
    if normalized == res_text:
        return 0
    return len(check_pattern.findall(normalized))


def _check_engine_errors(res_text: str, orig_text: str, declared_engine: str) -> Optional[ErrorMatch]:
    """가장 호환성이 높고 가중치가 높은 에러 시그니처를 반환."""
    best_match: Optional[ErrorMatch] = None
    
    for engine, compiled_data in _COMPILED_ENGINE_ERRORS.items():
        for pat, weight in compiled_data:
            res_matches = pat.findall(res_text)
            if not res_matches:
                continue
                
            orig_matches = pat.findall(orig_text) if orig_text else []
            res_count = len(res_matches)
            orig_count = len(orig_matches)
            
            if res_count > orig_count:
                compatibility_bonus = 50 if _is_engine_compatible(declared_engine, engine) else 0
                score = weight + compatibility_bonus
                
                if not best_match or score > best_match.score:
                    best_match = ErrorMatch(
                        engine=engine, err_str=res_matches[0], 
                        orig_count=orig_count, res_count=res_count, score=score
                    )
    return best_match


# ============================================================
# 메인 탐지 함수
# ============================================================
def detect_ssti(
        res_text: str,
        orig_text: Optional[str],
        payload_value: str,
        attack_type: str,
        expected_result: str,
) -> SSTIResult:
    """SSTI 취약점 탐지 코어 로직"""
    baseline_missing = not bool(orig_text)
    signals = {"baseline_missing": baseline_missing}

    if not res_text or not payload_value or not expected_result:
        return SSTIResult(False, Confidence.NONE, "unknown", signals=signals)

    # 응답 정규화 (HTML auto-escaping 대응)
    res_text_normalized = _normalize_response(res_text)
    orig_text_normalized = _normalize_response(orig_text or "")
    
    if res_text_normalized != res_text:
        signals["response_was_html_encoded"] = True

    if _is_expected_too_risky(expected_result):
        logger.debug(
            f"[SSTI] expected classified as risky (len={len(expected_result)}, "
            f"value='{expected_result[:30]}'). Scenario A will be skipped."
        )

    engine = _identify_engine(payload_value, attack_type)
    check_pattern = _get_result_pattern(expected_result)

    is_reflected = _is_payload_reflected(res_text_normalized, payload_value)
    
    if is_reflected:
        signals["is_reflected"] = True

    # ━━━ [오탐 방지 패치] ━━━
    # 1. 단순 반사 텍스트 제거 (normalized 기준)
    res_text_for_check = res_text_normalized
    if payload_value and is_reflected:
        res_text_for_check = res_text_normalized.replace(payload_value, "")

    # 2. 위험도 기반 차단 (엔트로피 휴리스틱)
    if _is_expected_too_risky(expected_result):
        is_evaluated = False
        signals["expected_too_risky_skipped"] = True
    else:
        evaluated_count = _check_expected_in_response(res_text_for_check, check_pattern)
        is_evaluated = evaluated_count > 0
    # ━━━ [패치 끝] ━━━

    # ============================================================
    # [시나리오 A] 연산 결과값이 응답에 존재
    # ============================================================
    if is_evaluated:
        orig_count = _check_expected_in_response(orig_text_normalized, check_pattern)  
        res_count = _check_expected_in_response(res_text_for_check, check_pattern)
        count_delta = res_count - orig_count
        signals["result_count_delta"] = count_delta

        if count_delta > 0:
            evidence = f"Computed result '{expected_result}' detected (Count: {orig_count} → {res_count})"
            confidence = Confidence.HIGH

            if is_reflected:
                evidence += " (Raw payload also reflected, but computation verified)"
            
            # 원본 기준 반사 횟수 기록
            payload_expected_count = len(check_pattern.findall(payload_value))
            payload_reflection_count = res_text.count(payload_value) if payload_value else 0
            signals["payload_reflection_count"] = payload_reflection_count
            
            # ━━━ 안전망: HTML 엔코딩 등 부분 반사 케이스 대비 ━━━
            # is_reflected=False여도 페이로드 일부가 응답에 살아있을 수 있음
            # 이 경우 격하 로직으로 한 번 더 거름
            effective_expected_count = payload_expected_count * max(1, payload_reflection_count)
            if (payload_reflection_count > 0 
                    and payload_expected_count > 0 
                    and count_delta <= effective_expected_count):
                if confidence.value > Confidence.MEDIUM.value:
                    confidence = Confidence.MEDIUM
                evidence += (
                    f" [Downgraded: Multi-reflection pattern "
                    f"(payload_reflected={payload_reflection_count}x, "
                    f"expected_in_payload={payload_expected_count}x)]"
                )

            if baseline_missing:
                if confidence.value > Confidence.MEDIUM.value:
                    confidence = Confidence.MEDIUM
                evidence += " [No Baseline Comparison]"

            return SSTIResult(True, confidence, engine, evidence, signals=signals)
            
        elif count_delta == 0 and orig_count > 0:
            signals["baseline_match_no_delta"] = True

    # ============================================================
    # [시나리오 B] 에러 기반 탐지 (normalized 기준)
    # ============================================================
    error_match = _check_engine_errors(res_text_normalized, orig_text_normalized, engine)
    
    if error_match:
        signals["error_count_delta"] = error_match.res_count - error_match.orig_count

        if engine == "unknown":
            signals["unknown_engine_match"] = True
            evidence = f"Engine error signature: {error_match.err_str} [Unknown declared engine]"
            return SSTIResult(
                True, Confidence.LOW, error_match.engine, evidence, 
                is_error_based=True, signals=signals
            )

        if _is_engine_compatible(engine, error_match.engine):
            evidence = (
                f"Engine error signature: {error_match.err_str} "
                f"(Count: {error_match.orig_count} → {error_match.res_count})"
            )
            return SSTIResult(
                True, Confidence.LOW, error_match.engine, evidence, 
                is_error_based=True, signals=signals
            )
            
        elif _is_engine_chained(engine, error_match.engine):
            signals["chained_engines_detected"] = {
                "declared": engine, 
                "detected": error_match.engine
            }
            evidence = (
                f"Chained Engine Detected: payload={engine}, error={error_match.engine} "
                f"(Signature: {error_match.err_str})"
            )
            return SSTIResult(
                True, Confidence.LOW, engine, evidence, 
                is_error_based=True, signals=signals
            )
            
        else:
            signals["engine_mismatch_dropped"] = True
            signals["cross_module_signal"] = {
                "type": "engine_mismatch_error",
                "declared_engine": engine,
                "detected_engine": error_match.engine,
                "error_string": error_match.err_str
            }
            return SSTIResult(
                False, Confidence.NONE, engine, 
                f"Engine Mismatch Dropped: payload={engine}, error={error_match.engine}", 
                is_error_based=False, signals=signals
            )

    # ============================================================
    # [시나리오 C] baseline_match_no_delta + 에러 없음 → 재검증 신호
    # ============================================================
    if signals.get("baseline_match_no_delta"):
        signals["requires_reverification"] = True
        evidence = (
            f"Pre-existing value matches '{expected_result}' but no error detected. "
            f"Module.py should re-verify with different expected_result."
        )
        return SSTIResult(False, Confidence.LOW, engine, evidence, signals=signals)

    # ============================================================
    # [시나리오 D] 미탐
    # ============================================================
    return SSTIResult(False, Confidence.NONE, engine, signals=signals)