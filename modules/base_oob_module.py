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
        # 1. 8자리 고유 토큰 생성
        token = uuid.uuid4().hex[:8]
        
        # 실제 타겟에 주입될 도메인
        oob_host = f"{token}.{self.oob_domain}"
        
        # Enum 타입 변환 방어 로직
        loc = getattr(surface, "param_location", "")
        loc_str = loc.name if hasattr(loc, "name") else str(loc)
        method_raw = getattr(surface, "method", "GET")
        method_str = getattr(method_raw, "value", str(method_raw))
        
        # 2. 메인 스캐너의 Webhook 리시버가 참조할 수 있도록 Redis에 매핑 데이터 저장
        r = await self._get_redis()
        meta_data = {
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
        
        # 토큰을 키로 하여 TTL(24시간)과 함께 저장 (Fire & Forget)
        await r.setex(f"oob_map:{token}", self.oob_ttl, json.dumps(meta_data))

        # 3. Payload 객체의 value 치환 후 복제본 반환
        new_value = payload.value.replace("[OOB_HOST]", oob_host)
        return dataclasses.replace(payload, value=new_value)

    async def analyze(self, response: Any, payload: Any, elapsed_time: float, 
                      original_res: Any = None, requester: Any = None) -> Tuple[bool, List[str], Any]:
        """
        OOB 공격은 응답(HTTP Response)에서 증거를 찾지 않음.
        """
        return False, [], payload