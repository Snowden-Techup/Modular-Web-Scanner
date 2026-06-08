from __future__ import annotations

import json
import logging
import os
import re 
from collections import defaultdict
from functools import lru_cache
from typing import Any, Set

from core.models import Payload

logger = logging.getLogger(__name__)

_SSTI_JSON_PATH = os.path.join("config", "payloads", "ssti", "ssti.json")
_SSTI_TXT_PATH = os.path.join("config", "payloads", "ssti", "ssti.txt")


def _map_risk_level(risk: str) -> str:
    """Normalize risk level to HIGH/MEDIUM/LOW."""
    risk_lower = str(risk or "").lower()
    if risk_lower in ("critical", "high"):
        return "HIGH"
    if risk_lower == "medium":
        return "MEDIUM"
    return "LOW"


def _normalize_attack_type(raw_attack_type: str) -> str:
    """Ensure attack_type is always in `ssti:<engine>` format."""
    value = str(raw_attack_type or "").strip()
    if not value:
        return "ssti:unknown"

    if value.startswith("ssti:"):
        parts = value.split(":")
        # analyzer.py 규격: "ssti:<engine_name>"만 허용
        if len(parts) >= 2 and parts[1]:
            return f"ssti:{parts[1]}"
        return "ssti:unknown"

    return f"ssti:{value}"


def _iter_json_items(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten v1.2.0 JSON schema while skipping `_meta*` keys."""
    items: list[dict[str, Any]] = []
    for category, category_items in data.items():
        if str(category).startswith("_meta"):
            continue
        if not isinstance(category_items, list):
            continue
        for item in category_items:
            if isinstance(item, dict):
                items.append(item)
    return items


def _extract_json_item(item: dict[str, Any]) -> tuple[str, str, str, str] | None:
    """Extract payload/attack/expected/risk explicitly from one JSON item."""
    payload_value = str(item.get("payload", "")).strip()
    expected_value = str(item.get("expected", "")).strip()
    if not payload_value or not expected_value:
        return None

    attack_type = _normalize_attack_type(str(item.get("attack_type", "ssti:unknown")))
    risk_level = _map_risk_level(str(item.get("risk_level", "LOW")))
    return (payload_value, attack_type, expected_value, risk_level)


def _load_json_payloads(file_path: str) -> tuple[tuple[str, str, str, str], ...]:
    """
    Load SSTI payload rows from v1.2.0 JSON.

    Returns:
        tuple[(payload, attack_type, expected, risk_level), ...]
    """
    rows: list[tuple[str, str, str, str]] = []
    with open(file_path, "r", encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)

    if not isinstance(data, dict):
        return tuple()

    for item in _iter_json_items(data):
        extracted = _extract_json_item(item)
        if extracted is not None:
            rows.append(extracted)
    return tuple(rows)


def _extract_txt_fields(parts: list[str]) -> tuple[str, str, str, str] | None:
    """Parse one TXT line split by `:::` with default fallback values."""
    payload_value = parts[0].strip() if parts else ""
    if not payload_value:
        return None

    attack_type = _normalize_attack_type(parts[1].strip() if len(parts) > 1 else "ssti:unknown")
    expected_value = parts[2].strip() if len(parts) > 2 and parts[2].strip() else payload_value
    risk_level = _map_risk_level(parts[3].strip() if len(parts) > 3 else "HIGH")
    return (payload_value, attack_type, expected_value, risk_level)


def _load_txt_payloads(file_path: str) -> tuple[tuple[str, str, str, str], ...]:
    """
    Load SSTI payload rows from TXT.

    TXT format:
        <payload>:::<attack_type>:::<expected>:::<risk_level>
    """
    rows: list[tuple[str, str, str, str]] = []
    with open(file_path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [part.strip() for part in line.split(":::")]
            extracted = _extract_txt_fields(parts)
            if extracted is not None:
                rows.append(extracted)
    return tuple(rows)


def _builtin_payload_schema() -> dict[str, list[dict[str, str]]]:
    """
    Built-in fallback payloads.

    """
    return {
        "_meta": {
            "schema_version": "1.2.0",
            "source": "built-in",
        },
        # generic 먼저 배치하여 First Wins 시 범용 분류가 우선되도록 유지
        "generic": [
            {
                "name": "generic arithmetic",
                "payload": "{{1337*1337}}",
                "expected": "1787569",
                "attack_type": "ssti:generic",
                "risk_level": "LOW",
                "description": "Generic arithmetic probe",
            },
            {
                "name": "python mro py3",
                "payload": "{{ ''.__class__.__mro__ }}",
                "expected": "<class 'str'>",
                "attack_type": "ssti:generic",
                "risk_level": "MEDIUM",
                "description": "Python3 MRO object string",
            },
            {
                "name": "python mro py2",
                "payload": "{{ ''.__class__.__mro__ }}",
                "expected": "<type 'str'>",
                "attack_type": "ssti:generic",
                "risk_level": "MEDIUM",
                "description": "Python2 MRO object string",
            },
            {
                "name": "os name posix",
                "payload": "{{ cycler.__init__.__globals__.os.name }}",
                "expected": "posix",
                "attack_type": "ssti:generic",
                "risk_level": "MEDIUM",
                "description": "OS fingerprint on unix-like host",
            },
            {
                "name": "os name nt",
                "payload": "{{ cycler.__init__.__globals__.os.name }}",
                "expected": "nt",
                "attack_type": "ssti:generic",
                "risk_level": "MEDIUM",
                "description": "OS fingerprint on windows host",
            },
        ],
        "jinja2": [
            {
                "name": "jinja2 arithmetic",
                "payload": "{{1337*1337}}",
                "expected": "1787569",
                "attack_type": "ssti:jinja2",
                "risk_level": "medium",
                "description": "Jinja2 arithmetic check",
            },
            {
                "name": "jinja2 config disclosure",
                "payload": "{{config}}",
                "expected": "<Config",
                "attack_type": "ssti:jinja2",
                "risk_level": "HIGH",
                "description": "Config object disclosure hint",
            },
        ],
        "twig": [
            {
                "name": "twig arithmetic",
                "payload": "{{1337*1337}}",
                "expected": "1787569",
                "attack_type": "ssti:twig",
                "risk_level": "low",
                "description": "Twig arithmetic check",
            }
        ],
        "freemarker": [
            {
                "name": "freemarker arithmetic",
                "payload": "${1337*1337}",
                "expected": "1787569",
                "attack_type": "ssti:freemarker",
                "risk_level": "MEDIUM",
                "description": "Freemarker arithmetic check",
            }
        ],
        "tornado": [
            {
                "name": "tornado arithmetic",
                "payload": "{{1337*1337}}",
                "expected": "1787569",
                "attack_type": "ssti:tornado",
                "risk_level": "medium",
                "description": "Tornado arithmetic check",
            }
        ],
    }


def _load_builtin_rows() -> tuple[tuple[str, str, str, str], ...]:
    """Convert built-in schema to normalized row tuples."""
    rows: list[tuple[str, str, str, str]] = []
    for item in _iter_json_items(_builtin_payload_schema()):
        extracted = _extract_json_item(item)
        if extracted is not None:
            rows.append(extracted)
    return tuple(rows)

# ============================================================
# Evasion 변조 (Level 0~3, lru_cache 적용)
# ============================================================
@lru_cache(maxsize=128)
def _mutate_cached(base_value: str, level: int) -> frozenset[str]:
    """
    SSTI 페이로드 변조 (lru_cache 적용 모듈 수준 함수).
    
    중요: 변형 후에도 expected는 원본과 같아야 함.
    (서버가 변형된 페이로드를 처리하면 동일한 결과 반환)
    
    레벨별 변형:
    - Level 0: 원본만
    - Level 1: 공백/포매팅 변형 (WAF 단순 패턴 매칭 우회)
    - Level 2: URL/HTML 인코딩
    - Level 3: 변수 분리, 이중 인코딩
    """
    # ReDoS 방지: 비정상 길이 입력은 원본만 반환
    if len(base_value) > 2000:
        return frozenset({base_value})
    
    if level <= 0:
        return frozenset({base_value})
    
    mutations: Set[str] = {base_value}
    
    # ─── Level 1: 공백/포매팅 변형 ───
    if level >= 1:
        lvl1: Set[str] = set()
        for val in list(mutations):
            # {{X}} → {{ X }} (공백 패딩)
            if "{{" in val and "}}" in val:
                spaced = val.replace("{{", "{{ ").replace("}}", " }}")
                lvl1.add(spaced)
            
            # ${X} → ${ X }  (단일 ${...} 형태만)
            m = re.match(r'^\$\{(.+)\}$', val)
            if m:
                lvl1.add("${ " + m.group(1) + " }")
            
            # {X*Y} (Smarty) → { X*Y }
            m2 = re.match(r'^\{([^{}]+)\}$', val)
            if m2 and not val.startswith("{{") and not val.startswith("${"):
                lvl1.add("{ " + m2.group(1) + " }")
            
            # 산술 주변 공백: 1337*1337 → 1337 * 1337
            if re.search(r'\w\*\w', val):
                lvl1.add(re.sub(r'(\w)\*(\w)', r'\1 * \2', val))
        
        mutations.update(lvl1)
    
    # ─── Level 2: URL/HTML 인코딩 ───
    if level >= 2:
        lvl2: Set[str] = set()
        for val in list(mutations):
            # 중괄호만 URL 인코딩 (Jinja2/Twig)
            if "{{" in val and "}}" in val:
                lvl2.add(val.replace("{{", "%7B%7B").replace("}}", "%7D%7D"))
            
            # ${...} 인코딩 (FreeMarker/SpEL)
            if val.startswith("${") and val.endswith("}"):
                lvl2.add("%24%7B" + val[2:-1] + "%7D")
            
            # HTML 엔티티 인코딩 (특수문자만)
            if "{" in val or "}" in val:
                encoded = val.replace("{", "&#123;").replace("}", "&#125;")
                if encoded != val:
                    lvl2.add(encoded)
        
        mutations.update(lvl2)
    
    # ─── Level 3: 변수 분리 / 이중 인코딩 ───
    if level >= 3:
        lvl3: Set[str] = set()
        for val in list(mutations):
            # Jinja2/Twig 변수 분리: {{config}} → {%set x=config%}{{x}}
            m = re.match(r'^\{\{\s*(\w+)\s*\}\}$', val)
            if m:
                var_name = m.group(1)
                lvl3.add("{%%set x=%s%%}{{x}}" % var_name)
            
            # 이중 URL 인코딩 (Jinja2/Twig)
            if "{{" in val and "}}" in val:
                lvl3.add(val.replace("{{", "%257B%257B").replace("}}", "%257D%257D"))
            
            # 따옴표 우회: 'sstivuln' → \\u0027sstivuln\\u0027
            if "'" in val:
                lvl3.add(val.replace("'", "\\u0027"))
        
        mutations.update(lvl3)
    
    return frozenset(mutations)


class PayloadMutator:
    """
    SSTI 페이로드를 동적으로 변조하여 WAF 우회 패턴 생성.
    
    캐시 함수 _mutate_cached()에 위임 (staticmethod + lru_cache 충돌 회피).
    """
    
    @staticmethod
    def mutate(base_value: str, level: int) -> frozenset[str]:
        """
        Args:
            base_value: 원본 페이로드 값
            level: 0~3 변조 강도
        
        Returns:
            frozenset[str]: 원본 + 변형 페이로드 집합 (중복 제거)
        """
        return _mutate_cached(base_value, level)


@lru_cache(maxsize=1)
def _load_base_payloads() -> tuple[Payload, ...]:
    """
    Load and cache base `Payload` objects.

    캐시 오염 방지를 위해 tuple만 반환한다.
    """
    rows, _ = _load_rows_and_expecteds()
    payloads: list[Payload] = []
    seen_values: set[str] = set()

    for payload_value, attack_type, _expected, risk_level in rows:
        # First Wins: 먼저 발견된 attack_type/risk_level을 유지
        if payload_value in seen_values:
            continue
        seen_values.add(payload_value)
        payloads.append(
            Payload(
                value=payload_value,
                attack_type=attack_type,
                risk_level=risk_level,
            )
        )
    return tuple(payloads)


@lru_cache(maxsize=1)
def _load_expected_entries() -> tuple[tuple[str, tuple[str, ...]], ...]:
    """
    Load and cache immutable expected map entries.

    Returns:
        tuple[(payload_value, (expected1, expected2, ...)), ...]
    """
    rows, _ = _load_rows_and_expecteds()
    expected_map: dict[str, list[str]] = defaultdict(list)
    for payload_value, _attack_type, expected_value, _risk_level in rows:
        if expected_value not in expected_map[payload_value]:
            expected_map[payload_value].append(expected_value)
    return tuple(
        (payload_value, tuple(expected_values))
        for payload_value, expected_values in expected_map.items()
    )


@lru_cache(maxsize=1)
def _load_rows_and_expecteds() -> tuple[tuple[tuple[str, str, str, str], ...], str]:
    """
    Load normalized payload rows by source priority.

    Returns:
        (rows, source) where source in {"json", "txt", "builtin"}
    """
    try:
        if os.path.exists(_SSTI_JSON_PATH):
            rows = _load_json_payloads(_SSTI_JSON_PATH)
            if rows:
                logger.info(f"[+] [SSTI] JSON 페이로드 로드: {len(rows)}개")
                return (rows, "json")
    except Exception as e:
        logger.info(f"[-] [SSTI] JSON 페이로드 로드 실패: {e}")

    try:
        if os.path.exists(_SSTI_TXT_PATH):
            rows = _load_txt_payloads(_SSTI_TXT_PATH)
            if rows:
                logger.info(f"[+] [SSTI] TXT 페이로드 로드: {len(rows)}개")
                return (rows, "txt")
    except Exception as e:
        logger.info(f"[-] [SSTI] TXT 페이로드 로드 실패: {e}")

    rows = _load_builtin_rows()
    logger.info(f"[+] [SSTI] 내장 페이로드 사용: {len(rows)}개")
    return (rows, "builtin")


def get_ssti_payloads(evasion_level: int = 0) -> tuple[list[Payload], dict[str, list[str]]]:
    """
    Return SSTI payloads and expected result mapping (Option A: 1:N).
    
    Args:
        evasion_level: 0=off, 1=basic WAF bypass, 2=encoding, 3=obfuscation
    
    Returns:
        (payloads_list, expected_map)
        - payloads_list: 코어가 사용하는 순수 Payload 객체 리스트 (중복 제거됨)
        - expected_map: {payload_value: [expected_value, ...]} 1:N 매핑
    
    처리 순서:
        1. _load_base_payloads() → 원본 페이로드 (캐싱)
        2. PayloadMutator.mutate() → 변조 (level > 0인 경우)
        3. expected_map 동기화 (변형 페이로드도 원본 expected 상속)
    """
    level = max(0, min(3, int(evasion_level)))
    
    base_payloads = _load_base_payloads()  # tuple[Payload, ...] (immutable cache)
    expected_entries = _load_expected_entries()  # tuple[(value, tuple[expected, ...]), ...]
    
    # 호출자 변형으로 캐시가 오염되지 않도록 새 컨테이너를 매 호출마다 생성
    payloads_list = list(base_payloads)
    expected_map = {value: list(expected_values) for value, expected_values in expected_entries}
    
    # ━━━ Evasion 변조 적용 (Phase 2) ━━━
    if level > 0:
        seen_values: Set[str] = {p.value for p in payloads_list}
        mutated_payloads: list[Payload] = []
        
        for base in base_payloads:
            mutations = PayloadMutator.mutate(base.value, level)
            base_expected = expected_map.get(base.value, [])
            
            for mutated_value in mutations:
                if mutated_value in seen_values:
                    continue
                seen_values.add(mutated_value)
                
                mutated_payloads.append(Payload(
                    value=mutated_value,
                    attack_type=base.attack_type,
                    risk_level=base.risk_level,
                ))
                
                # 변형 페이로드도 원본의 expected를 상속 (1:N 매핑 유지)
                expected_map[mutated_value] = list(base_expected)
        
        payloads_list.extend(mutated_payloads)
        logger.info(
            f"[+] [SSTI] 변조 적용 (Level {level}): "
            f"{len(base_payloads)} → {len(payloads_list)}개"
        )
    
    return (payloads_list, expected_map)


__all__ = ("get_ssti_payloads", "PayloadMutator")