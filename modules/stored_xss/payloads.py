import json
import logging
import threading
import uuid
import base64
import re
from pathlib import Path
from typing import List, Dict, Optional, Set, Any
from core.models import Payload
from enum import Enum

logger = logging.getLogger(__name__)


class PayloadCategory(Enum):
    BASIC = "basic"
    EVENT_HANDLER = "event_handler"
    CSTI = "csti"
    PROTOCOL = "protocol"
    MODERN_HTML5 = "modern_html5"
    SPA_FRAMEWORKS = "spa_frameworks"
    MARKDOWN_WYSIWYG = "markdown_wysiwyg"
    PORTSWIGGER_CORE = "portswigger_core"
    POLYGLOT_REFINED = "polyglot_refined"
    POLYGLOT = "polyglot"


# ==================== 안전한 경로 설정 ====================
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent
CONFIG_DIR = (PROJECT_ROOT / "config" / "payloads" / "xss").resolve()
PAYLOAD_FILE_PATH = (CONFIG_DIR / "xss.json").resolve()

_PAYLOAD_DATABASE_CACHE: Dict[str, List[dict]] = {}
_CACHE_LOCK = threading.Lock()


def _validate_schema(data: Any) -> bool:
    if not isinstance(data, dict): return False
    for category, payloads in data.items():
        if not isinstance(category, str) or not isinstance(payloads, list): return False
        for item in payloads:
            if not isinstance(item, dict) or "value" not in item: return False
    return True


def load_payload_database() -> Dict[str, List[dict]]:
    global _PAYLOAD_DATABASE_CACHE
    if _PAYLOAD_DATABASE_CACHE: return _PAYLOAD_DATABASE_CACHE

    with _CACHE_LOCK:
        if _PAYLOAD_DATABASE_CACHE: return _PAYLOAD_DATABASE_CACHE
        if not PAYLOAD_FILE_PATH.exists():
            return {}
        try:
            with open(PAYLOAD_FILE_PATH, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)
            if _validate_schema(raw_data):
                _PAYLOAD_DATABASE_CACHE = raw_data
                return _PAYLOAD_DATABASE_CACHE
            else:
                return {}
        except Exception:
            return {}


def reload_payloads() -> None:
    global _PAYLOAD_DATABASE_CACHE
    with _CACHE_LOCK:
        _PAYLOAD_DATABASE_CACHE.clear()
    load_payload_database()


class PayloadMutator:
    """XSS 페이로드를 동적으로 변조하여 WAF 우회 패턴을 생성합니다."""

    @staticmethod
    def mutate(base_value: str, level: int) -> Set[str]:
        mutations = set()
        mutations.add(base_value)  # 원본 유지

        # [Level 1] Basic WAF Bypass: 구문 형태 및 공백 변형
        if level >= 1:
            lvl1_mutations = set()
            for val in mutations:
                # 1. 태그명 첫 글자 대문자화 (e.g., <script> -> <Script>)
                capitalized = re.sub(r'<([a-zA-Z])([a-zA-Z0-9]*)', lambda m: f"<{m.group(1).upper()}{m.group(2)}", val)
                lvl1_mutations.add(capitalized)

                # 2. 이벤트 핸들러 앞 공백을 슬래시(/)로 치환 (e.g., <img onerror= -> <img/onerror=)
                slashed = re.sub(r'\s+(on\w+\s*=)', r'/\1', val, flags=re.IGNORECASE)
                lvl1_mutations.add(slashed)
            mutations.update(lvl1_mutations)

        # [Level 2] Advanced WAF Bypass: JS 인코딩 및 괄호 우회
        if level >= 2:
            lvl2_mutations = set()
            for val in mutations:
                # 1. 괄호 대신 백틱 사용 (e.g., alert('X') -> alert`X`)
                if "alert('{{MARKER}}')" in val:
                    lvl2_mutations.add(val.replace("alert('{{MARKER}}')", "alert`{{MARKER}}`"))

                # 2. JS 유니코드 이스케이프 (alert -> \u0061lert)
                if "alert" in val:
                    lvl2_mutations.add(val.replace("alert", "\\u0061lert"))
            mutations.update(lvl2_mutations)

        # [Level 3] Obfuscation: 실행 흐름 은닉
        if level >= 3:
            lvl3_mutations = set()
            for val in mutations:
                # 1. Base64 eval 난독화
                if "alert('{{MARKER}}')" in val:
                    lvl3_mutations.add(val.replace("alert('{{MARKER}}')", "eval(atob('{{B64_MARKER}}'))"))

                # 2. 문자열 쪼개기 (top['al'+'ert'])
                if "alert('{{MARKER}}')" in val:
                    lvl3_mutations.add(val.replace("alert('{{MARKER}}')", "top['al'+'ert']('{{MARKER}}')"))
            mutations.update(lvl3_mutations)

        return mutations


def _resolve_stored_xss_categories(
        categories: Optional[List[PayloadCategory]],
) -> List[PayloadCategory]:
    return categories if categories is not None else list(PayloadCategory)


def _iter_stored_xss_payload_entries(
        *,
        categories: Optional[List[PayloadCategory]] = None,
        max_risk_level: Optional[str] = None,
        mutation_level: int = 1,
):
    """build_stored_xss_payloads / count_stored_xss_payloads 공통 순회."""
    target_categories = _resolve_stored_xss_categories(categories)
    risk_order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    max_risk_value = risk_order.get(max_risk_level, 4) if max_risk_level else 4
    seen_values: Set[str] = set()
    db = load_payload_database()

    for category in target_categories:
        category_payloads = db.get(category.value, [])
        for config in category_payloads:
            base_value = config.get("value")
            risk_level = config.get("risk_level", "Medium")

            if not isinstance(risk_level, str):
                risk_level = "Medium"

            if not base_value or not isinstance(base_value, str):
                continue
            if risk_order.get(risk_level, 0) > max_risk_value:
                continue

            mutated_values = PayloadMutator.mutate(base_value, mutation_level)
            for mutated_value in mutated_values:
                marker = f"xss_{uuid.uuid4().hex[:6]}"
                b64_marker = base64.b64encode(f"alert('{marker}')".encode()).decode()
                char_marker = ",".join(str(ord(c)) for c in marker)

                tracked_value = mutated_value.replace("{{MARKER}}", marker)
                tracked_value = tracked_value.replace("%7B%7BMARKER%7D%7D", marker)
                tracked_value = tracked_value.replace("{{B64_MARKER}}", b64_marker)
                tracked_value = tracked_value.replace("{{CHAR_MARKER}}", char_marker)

                if tracked_value in seen_values:
                    continue
                seen_values.add(tracked_value)
                yield tracked_value, risk_level


def count_stored_xss_payloads(
        categories: Optional[List[PayloadCategory]] = None,
        max_risk_level: Optional[str] = None,
        mutation_level: int = 1,
) -> int:
    """mutation·리스크 필터 적용 후 실제 실행 페이로드 수 (get_payloads와 동일 기준)."""
    return sum(1 for _ in _iter_stored_xss_payload_entries(
        categories=categories,
        max_risk_level=max_risk_level,
        mutation_level=mutation_level,
    ))


def build_stored_xss_payloads(
        categories: Optional[List[PayloadCategory]] = None,
        max_risk_level: Optional[str] = None,
        mutation_level: int = 1,
) -> List[Payload]:
    payloads = []
    for tracked_value, risk_level in _iter_stored_xss_payload_entries(
        categories=categories,
        max_risk_level=max_risk_level,
        mutation_level=mutation_level,
    ):
        payloads.append(
            Payload(value=tracked_value, attack_type="stored_xss", risk_level=risk_level)
        )
    return payloads


def get_payload_count() -> dict:
    db = load_payload_database()
    return {c.value: len(db.get(c.value, [])) for c in PayloadCategory}


def get_all_categories() -> List[str]:
    return [c.value for c in PayloadCategory]