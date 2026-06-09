import os
import json
import uuid
import dataclasses
from typing import Any, Tuple, List
import redis.asyncio as redis

from modules.base_module import BaseModule
from core.models import Payload

class BaseOOBModule(BaseModule):
    def __init__(self, name: str, **kwargs):
        super().__init__(name)
        
        default_oob_domain = os.getenv("OOB_DOMAIN", "oob.snowden.kr")
        self.oob_domain = kwargs.get("oob_domain", default_oob_domain)
        
        # 도커 환경변수(REDIS_URL) 반영
        default_redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.redis_url = kwargs.get("redis_url", default_redis_url)
        
        self.oob_ttl = kwargs.get("oob_ttl", 86400)  # 토큰 유효기간: 24시간
        
        # Scan ID 저장
        self.scan_id = kwargs.get("scan_id", "UNKNOWN_SCAN_ID")
        
        # 자동으로 감지된 모드
        self.oob_mode = kwargs.get("oob_mode", "polling").lower()
        
        # CLI(polling) 모드일 때 토큰과 타겟 매핑 정보를 저장할 리스트
        self.generated_tokens = []

        # Redis 커넥션 풀 (지연 할당)
        self._redis = None

    async def _get_redis(self) -> redis.Redis:
        """Redis 클라이언트 싱글톤 반환 (Async 이벤트 루프 호환)"""
        if self._redis is None:
            self._redis = redis.from_url(self.redis_url, decode_responses=True)
        return self._redis

    async def bind_payload(self, surface: Any, parameter: str, payload: Payload) -> Payload:
        """
        엔진 훅: 워커가 HTTP 요청을 보내기 직전에 호출.
        """
        # 1. 1바이트 Prefix 포함한 9바이트 토큰 생성
        raw_token = uuid.uuid4().hex[:8]
        if self.oob_mode == "webhook":
            token = f"w{raw_token}"  # SaaS 모드: w (웹훅)
        else:
            token = f"c{raw_token}"  # CLI 모드: c (폴링)
            
        # 실제 타겟에 주입될 도메인
        oob_host = f"{token}.{self.oob_domain}"
        
        # Enum 타입 변환 방어 로직
        loc = getattr(surface, "param_location", "")
        loc_str = loc.name if hasattr(loc, "name") else str(loc)
        method_raw = getattr(surface, "method", "GET")
        method_str = getattr(method_raw, "value", str(method_raw))
        
        meta_data = {
            "token": token,  # 메모리 대조를 위해 토큰값 포함
            "scan_id": self.scan_id,
            "module_name": self.name,
            "target": {
                "url": getattr(surface, "url", ""),
                "method": method_str,
                "location": loc_str,
                "parameter": parameter
            },
            "attack_info": {
                "payload_value": payload.value.replace("[OOB_HOST]", oob_host),
                "type": getattr(payload, "attack_type", "OOB"),
                "risk_level": getattr(payload, "risk_level", "High")
            }
        }
        
        # 2. 모드에 따른 매핑 데이터 분기 저장
        if self.oob_mode == "webhook":
            # SaaS: Redis에 저장 (webhook 수신 시 조회용)
            r = await self._get_redis()
            await r.setex(f"oob_map:{token}", self.oob_ttl, json.dumps(meta_data))
            # DB fallback을 위해 메모리에도 기록 (surface_obj 제외 — 직렬화 불가)
            self.generated_tokens.append(meta_data)
        else:
            # CLI: Redis 없이 메모리에만 저장
            memory_data = meta_data.copy()
            memory_data["surface_obj"] = surface
            self.generated_tokens.append(memory_data)

        # 3. Payload 객체의 value 치환 후 복제본 반환
        new_value = payload.value.replace("[OOB_HOST]", oob_host)
        return dataclasses.replace(payload, value=new_value)

    async def analyze(self, response: Any, payload: Any, elapsed_time: float, 
                      original_res: Any = None, requester: Any = None) -> Tuple[bool, List[str], Any]:
        """
        OOB 공격은 응답(HTTP Response)에서 증거를 찾지 않음.
        """
        return False, [], payload