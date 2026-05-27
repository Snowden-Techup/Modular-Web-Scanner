import os
import json
import urllib.parse
import re
import dataclasses
import random
import asyncio
from dataclasses import dataclass
from typing import Iterator, Any, Tuple, List, Optional, Iterable

from modules.base_module import BaseModule
from modules.sqli.payloads import get_sqli_payloads
from modules.sqli.analyzer import detect_sqli, verify_sqli_logic
from core.models import Payload

@dataclass(frozen=True, slots=True)
class SQLiInternalPayload(Payload):
    target_dbms: str = "All"
    _is_serial: bool = False
    _real_time_value: Optional[str] = None

class SQLiModule(BaseModule):
    def __init__(self, **kwargs):
        super().__init__("SQL Injection")
        self.allow_redirects = False
        self.exploit_signatures = self._load_json("exploit_errors.json")
        self.syntax_signatures = self._load_json("syntax_errors.json")
        self.mismatch_signatures = self._load_json("mismatch_errors.json")
        
        # CLI에서 입력받은 DBMS 텍스트 정규화 매핑 (기본값: all)
        raw_dbms = kwargs.get('target_dbms', 'all').lower()
        if raw_dbms == 'mysql': self.target_dbms = "MySQL"
        elif raw_dbms in ('mssql', 'microsoft sql server'): self.target_dbms = "Microsoft SQL Server"
        elif raw_dbms == 'oracle': self.target_dbms = "Oracle"
        elif raw_dbms in ('postgres', 'postgresql'): self.target_dbms = "PostgreSQL"
        elif raw_dbms == 'sqlite': self.target_dbms = "SQLite"
        elif raw_dbms == 'access': self.target_dbms = "MS Access"
        else: self.target_dbms = "all"
        
        self.evasion_level = kwargs.get('evasion_level', 0)
        self.include_time_based = kwargs.get('include_time_based', False)
        self.max_time_payloads = kwargs.get('max_time_payloads', 0)
        self.random_seed = kwargs.get('random_seed', 37)
        
        self._global_time_lock = asyncio.Lock()
        self._fast_per_param = 0
        self._known_targets = set()
        self._total_fast_expected = 0
        self._global_fast_completed = 0
        self._counter_lock = asyncio.Lock()
        
        # 이벤트 기반 장벽을 통해 시간 페이로드 직렬 처리
        self._barrier_event = asyncio.Event()
        self._time_attack_in_flight = 0
        self._time_phase_active = False

    def _load_json(self, filename: str) -> list:
        file_path = os.path.join("config", "payloads", "sqli", filename)
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def _is_time_payload(self, payload: Payload) -> bool:
        attack_type = str(getattr(payload, "attack_type", "")).lower()
        return "time" in attack_type or "stacked" in attack_type

    def get_target_parameters(self, surface: Any, all_params: Iterable[str]) -> Iterable[str]:
        if self._fast_per_param == 0:
            self.get_payload_count()
        params = list(all_params)
        url = getattr(surface, "url", "")
        method = getattr(surface, "method", "GET")
        for p in params:
            tid = (method, url, p)
            if tid not in self._known_targets:
                self._known_targets.add(tid)
                self._total_fast_expected += self._fast_per_param
        return params

    def get_payload_count(self) -> int:
        filtered = get_sqli_payloads(self.target_dbms)
        
        fast_c = sum(1 for p in filtered if not self._is_time_payload(p))
        time_c = sum(1 for p in filtered if self._is_time_payload(p))
        
        selected_time_count = 0
        if self.include_time_based:
            limit = self.max_time_payloads if self.max_time_payloads > 0 else time_c
            selected_time_count = min(limit, time_c)
        
        multiplier = self.evasion_level + 1
        self._fast_per_param = fast_c * multiplier
        return self._fast_per_param + (selected_time_count * multiplier)

    def get_payloads(self) -> Iterator[Payload]:
        if self._fast_per_param == 0: 
            self.get_payload_count()

        # payload.py 에서 필터링된 페이로드 리스트 로드
        filtered = get_sqli_payloads(self.target_dbms)
        
        fast_payloads = [p for p in filtered if not self._is_time_payload(p)]
        time_payloads = [p for p in filtered if self._is_time_payload(p)]

        # 1. 일반 페이로드 생성
        for level in range(self.evasion_level + 1):
            for p in fast_payloads:
                yield SQLiInternalPayload(
                    value=self._apply_evasion_by_level(p.value, level),
                    attack_type=p.attack_type,
                    risk_level=p.risk_level,
                    target_dbms=getattr(p, 'target_dbms', 'Generic'),
                    _is_serial=False
                )

        # 2. 시간 기반 페이로드 생성
        if self.include_time_based and time_payloads:
            random.seed(self.random_seed)
            limit = self.max_time_payloads if self.max_time_payloads > 0 else len(time_payloads)
            selected = random.sample(time_payloads, min(limit, len(time_payloads)))
            
            for level in range(self.evasion_level + 1):
                for p in selected:
                    yield SQLiInternalPayload(
                        value="1",
                        attack_type=p.attack_type,
                        risk_level=p.risk_level,
                        target_dbms=getattr(p, 'target_dbms', 'Generic'),
                        _is_serial=True,
                        _real_time_value=self._apply_evasion_by_level(p.value, level)
                    )

    def _apply_evasion_by_level(self, value: str, level: int) -> str:
        if level == 0: return value
        if level >= 1:
            value = value.replace("SELECT", "sElEcT").replace("UNION", "uNiOn")\
                         .replace("AND", "aNd").replace("OR", "oR")\
                         .replace("CASE", "cAsE").replace("WHEN", "wHeN")
        if level >= 2:
            value = value.replace(" ", "/**/")
        if level >= 3:
            value = urllib.parse.quote(urllib.parse.quote(value)) + "%00"
        return value

    async def analyze(self, response: Any, payload: Any, elapsed_time: float, 
                      original_res: Any = None, requester: Any = None) -> Tuple[bool, List[str], Any]:
        is_serial = getattr(payload, "_is_serial", False)

        # [A] 일반 페이로드 분석 (병렬)
        if not is_serial:
            # 시간 페이즈 종료까지 대기
            while self._time_phase_active:
                await asyncio.sleep(2.0)

            try:
                is_hit, evidences, has_syntax_error = detect_sqli(
                    response=response, payload=payload, elapsed_time=elapsed_time,
                    exploit_signatures=self.exploit_signatures,
                    syntax_signatures=self.syntax_signatures,
                    mismatch_signatures=self.mismatch_signatures,
                    original_res=original_res
                )
                final_hit, final_evidences = await verify_sqli_logic(
                    response, payload, original_res, requester, is_hit, evidences, has_syntax_error, self.syntax_signatures
                )
                return final_hit, final_evidences, payload
            finally:
                async with self._counter_lock:
                    self._global_fast_completed += 1
                    if self._global_fast_completed >= self._total_fast_expected and self._total_fast_expected > 0:
                        if not self._barrier_event.is_set():
                            self._barrier_event.set()

        # [B] 시간 기반 페이로드 분석 (직렬)
        if is_serial and requester:
            async with self._counter_lock:
                self._time_attack_in_flight += 1

            try:
                # 1. 장벽 대기
                if not self._barrier_event.is_set():
                    last_completed = -1
                    stuck_count = 0
                    
                    while not self._barrier_event.is_set():
                        try:
                            await asyncio.wait_for(self._barrier_event.wait(), timeout=10.0)
                        except asyncio.TimeoutError:
                            current_completed = self._global_fast_completed
                            
                            if current_completed == last_completed:
                                stuck_count += 1
                            else:
                                stuck_count = 0
                                last_completed = current_completed
                            
                            # 30초(10초 * 3) 동안 일반 페이로드 완료 없으면 강제 돌파
                            if stuck_count >= 3:
                                if not self._time_phase_active:
                                    print(f"\n[!] Deadlock Breaker: Network drop-offs detected. Forcing time-based phase (SQLi).")
                                self._barrier_event.set()
                                break
                    
                if not self._time_phase_active:
                    print(f"\n[★TRANSITION] Barrier cleared. Starting REAL time-based SQLi attacks!")
                    self._time_phase_active = True

                # 2. 전역 직렬 실행 락
                async with self._global_time_lock:
                    real_val = getattr(payload, "_real_time_value", "1")
                    actual_payload = dataclasses.replace(payload, value=real_val)
                    
                    try:
                        start_ts = asyncio.get_event_loop().time()
                        real_res = await requester(real_val)
                        real_elapsed = asyncio.get_event_loop().time() - start_ts
                        
                        # 서버 회복 대기
                        await asyncio.sleep(4.5)

                        is_hit, evidences, has_syntax_error = detect_sqli(
                            response=real_res, payload=actual_payload, elapsed_time=real_elapsed,
                            exploit_signatures=self.exploit_signatures,
                            syntax_signatures=self.syntax_signatures,
                            mismatch_signatures=self.mismatch_signatures,
                            original_res=original_res
                        )

                        if is_hit and not any(tag in str(evidences) for tag in ["[Time]", "[Error]", "[Reflection]"]):
                            is_hit, evidences = await verify_sqli_logic(
                                real_res, actual_payload, original_res, requester, is_hit, evidences, has_syntax_error, self.syntax_signatures
                            )
                        return is_hit, evidences, actual_payload

                    except asyncio.TimeoutError:
                        is_hit, evidences, _ = detect_sqli(
                            response=None, payload=actual_payload, elapsed_time=15.0,
                            exploit_signatures=self.exploit_signatures,
                            syntax_signatures=self.syntax_signatures,
                            mismatch_signatures=self.mismatch_signatures,
                            original_res=original_res
                        )
                        return True, evidences, actual_payload
            finally:
                async with self._counter_lock:
                    self._time_attack_in_flight -= 1
                    if self._time_attack_in_flight == 0:
                        if self._time_phase_active:
                            print(f"[★TRANSITION] Going back to normal SQLi payloads")
                            self._barrier_event.clear()
                            self._time_phase_active = False

        return False, [], payload