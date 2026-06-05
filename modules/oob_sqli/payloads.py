import os
from dataclasses import dataclass
from typing import List

@dataclass(frozen=True, slots=True)
class Payload:
    value: str
    attack_type: str
    risk_level: str
    target_dbms: str = "Generic"

def _resolve_payload_file() -> str | None:
    candidates = [
        os.path.join("config", "payloads", "oob_sqli", "oob_sqli.txt"),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return None

def get_oob_sqli_payloads(target_filter: str = "all") -> List[Payload]:
    """
    target_filter("all", "MySQL", "Oracle" 등)에 해당하는 
    OOB SQLi 페이로드만 로드하여 객체 리스트로 반환합니다.
    """
    payloads = []
    file_path = _resolve_payload_file()
    if not file_path:
        return []

    target_filter_lower = target_filter.lower()

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":::" not in line:
                continue

            parts = [p.strip() for p in line.split(":::", 3)]

            if len(parts) >= 4:
                raw_value = parts[0]
                attack_type = parts[1]
                risk_level = parts[2]
                dbms = parts[3]

                # [1] DBMS 필터링 적용
                if target_filter_lower != "all" and target_filter_lower != dbms.lower():
                    continue

                # [2] 페이로드 객체 생성
                payloads.append(Payload(
                    value=raw_value,
                    attack_type=attack_type,
                    risk_level=risk_level,
                    target_dbms=dbms
                ))
                
    return payloads