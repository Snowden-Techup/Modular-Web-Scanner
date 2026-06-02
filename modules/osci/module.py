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
from modules.osci.payloads import get_osci_payloads
from modules.osci.analyzer import detect_osci, verify_osci_logic
from core.models import Payload

@dataclass(frozen=True, slots=True)
class OSCiInternalPayload(Payload):
    target_os: str = "Unix"
    action_level: str = "SHELL"
    _is_serial: bool = False
    _real_time_value: Optional[str] = None

class OSCiModule(BaseModule):
    def __init__(self, **kwargs):
        super().__init__("OS Command Injection")
        
        # CLI 입력 매핑
        raw_os = kwargs.get('target_os', 'linux').lower()
        if raw_os == 'windows':
            self.target_os = "Windows"
        elif raw_os == 'all':
            self.target_os = "all"
        else:
            self.target_os = "Unix"

        self.allow_redirects = False
        self.evasion_level = kwargs.get('evasion_level', 0)
        self.include_time_based = kwargs.get('include_time_based', False)
        self.max_time_payloads = kwargs.get('max_time_payloads', 0)
        self.random_seed = kwargs.get('random_seed', 37)
        
        self._global_time_lock = asyncio.Lock()
        self._counter_lock = asyncio.Lock()
        
        self._fast_per_param = 0
        self._time_per_param = 0
        
        self._global_completed_payloads = 0  # 완료된 페이로드 카운트
        self._current_param_index = 1        # 현재 진행 중인 파라미터 번호
        
        # 이벤트 기반 장벽을 통해 시간 페이로드 직렬 처리
        self._barrier_event = asyncio.Event()
        self._time_attack_in_flight = 0
        self._time_phase_active = False

    def _is_time_payload(self, payload: Payload) -> bool:
        attack_type = str(getattr(payload, "attack_type", "")).lower()
        return "time-based" in attack_type or "time" in attack_type

    def get_target_parameters(self, surface: Any, all_params: Iterable[str]) -> Iterable[str]:
        if self._fast_per_param == 0 and self._time_per_param == 0:
            self.get_payload_count()
        return list(all_params)

    def get_payload_count(self) -> int:
        all_raw = get_osci_payloads(self.target_os)
        
        fast_c = sum(1 for p in all_raw if not self._is_time_payload(p))
        time_c = sum(1 for p in all_raw if self._is_time_payload(p))
        
        selected_time_count = 0
        if self.include_time_based:
            limit = self.max_time_payloads if self.max_time_payloads > 0 else time_c
            selected_time_count = min(limit, time_c)
        
        multiplier = self.evasion_level + 1
        
        # 각 파라미터당 할당될 일반/시간 페이로드 개수 저장
        self._fast_per_param = fast_c * multiplier
        self._time_per_param = selected_time_count * multiplier
        
        return self._fast_per_param + self._time_per_param

    def get_payloads(self) -> Iterator[Payload]:
        if self._fast_per_param == 0 and self._time_per_param == 0: 
            self.get_payload_count()

        filtered = get_osci_payloads(self.target_os)
        
        fast_payloads = [p for p in filtered if not self._is_time_payload(p)]
        time_payloads = [p for p in filtered if self._is_time_payload(p)]

        # 일반 페이로드 (병렬)
        for level in range(self.evasion_level + 1):
            for p in fast_payloads:
                yield OSCiInternalPayload(
                    value=self._apply_evasion_by_level(p.value, level, p.target_os, p.action_level),
                    attack_type=p.attack_type,
                    risk_level=p.risk_level,
                    target_os=p.target_os,
                    action_level=p.action_level,
                    _is_serial=False
                )

        # 시간 기반 페이로드 (직렬)
        if self.include_time_based and time_payloads:
            random.seed(self.random_seed)
            limit = self.max_time_payloads if self.max_time_payloads > 0 else len(time_payloads)
            selected_indices = random.sample(range(len(time_payloads)), min(limit, len(time_payloads)))
            
            for level in range(self.evasion_level + 1):
                for idx in selected_indices:
                    p = time_payloads[idx]
                    yield OSCiInternalPayload(
                        value="1",
                        attack_type=p.attack_type,
                        risk_level=p.risk_level,
                        target_os=p.target_os,
                        action_level=p.action_level,
                        _is_serial=True,
                        _real_time_value=self._apply_evasion_by_level(p.value, level, p.target_os, p.action_level),
                    )

    def _apply_evasion_by_level(self, value: str, level: int, t_os: str, action_level: str) -> str:
        if level == 0:
            return value
        
        # Level 1: 공백 우회
        if level >= 1:
            if t_os == "Unix":
                value = value.replace(" ", "${IFS}")
            else:
                if "PS" not in action_level:
                    value = value.replace(" ", ",")
        
        # Level 2: 키워드 난독화
        if level >= 2:
            if t_os == "Unix":
                value = value.replace("echo", "e'c'ho")
                value = value.replace("cat", "c'a't")
            else:
                value = value.replace("echo", "ec^ho")
                value = value.replace("set", "s^et")

                if "PS" in action_level:
                    value = value.replace("Write-Output", "W'rite-O'utput")
        
        # Level 3: URL 인코딩
        if level >= 3:
            value = urllib.parse.quote(value)
        
        return value

    async def analyze(self, response: Any, payload: Any, elapsed_time: float, 
                      original_res: Any = None, requester: Any = None) -> Tuple[bool, List[str], Any]:
        is_serial = getattr(payload, "_is_serial", False)

        # [A] 일반 페이로드 분석 (병렬)
        if not is_serial:
            while self._time_phase_active:
                await asyncio.sleep(2.0)

            try:
                is_hit, evidences = await detect_osci(
                    response=response,
                    payload=payload,
                    elapsed_time=elapsed_time,
                    original_res=original_res,
                    requester=requester
                )
                
                if is_hit:
                    final_hit, final_evidences = await verify_osci_logic(
                        response, payload, original_res, requester, is_hit, evidences
                    )
                    return final_hit, final_evidences, payload
                
                return is_hit, evidences, payload
            finally:
                async with self._counter_lock:
                    self._global_completed_payloads += 1
                    
                    n = self._current_param_index
                    # n * (일반 페이로드 개수) + (n-1) * (시간 페이로드 개수)
                    target_count = (n * self._fast_per_param) + ((n - 1) * self._time_per_param)
                    
                    if self._global_completed_payloads >= target_count:
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
                            current_completed = self._global_completed_payloads
                            
                            if current_completed == last_completed:
                                stuck_count += 1
                            else:
                                stuck_count = 0
                                last_completed = current_completed
                            # 30초(10초 * 3) 동안 일반 페이로드 완료 없으면 강제 돌파
                            if stuck_count >= 3:
                                self._barrier_event.set()
                                break
                        
                if not self._time_phase_active:
                    self._time_phase_active = True
                    await asyncio.sleep(4.5)

                # 2. 전역 직렬 실행 락
                async with self._global_time_lock:
                    real_val = getattr(payload, "_real_time_value", "test")
                    actual_payload = dataclasses.replace(payload, value=real_val)
                    
                    try:
                        start_ts = asyncio.get_event_loop().time()
                        real_res = await requester(real_val)
                        real_elapsed = asyncio.get_event_loop().time() - start_ts
                        
                        await asyncio.sleep(4.5)

                        is_hit, evidences = await detect_osci(
                            response=real_res,
                            payload=actual_payload,
                            elapsed_time=real_elapsed,
                            original_res=original_res,
                            requester=requester
                        )

                        if is_hit and "[Time]" not in str(evidences):
                            is_hit, evidences = await verify_osci_logic(
                                real_res, actual_payload, original_res, requester, is_hit, evidences
                            )
                        return is_hit, evidences, actual_payload

                    except asyncio.TimeoutError:
                        is_hit, evidences = await detect_osci(
                            response=None,
                            payload=actual_payload,
                            elapsed_time=15.0,
                            original_res=original_res,
                            requester=requester
                        )
                        return True, evidences, actual_payload
            finally:
                async with self._counter_lock:
                    self._global_completed_payloads += 1
                    self._time_attack_in_flight -= 1
                    if self._time_attack_in_flight == 0:
                        if self._time_phase_active:
                            self._barrier_event.clear()
                            self._time_phase_active = False
                            self._current_param_index += 1
                            await asyncio.sleep(30.0)

        return False, [], payload