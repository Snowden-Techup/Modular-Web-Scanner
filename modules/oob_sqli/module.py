import urllib.parse
import dataclasses
from typing import Iterator, Any, Iterable
from modules.base_oob_module import BaseOOBModule
from modules.oob_sqli.payload import get_oob_sqli_payloads
from core.models import Payload

@dataclasses.dataclass(frozen=True, slots=True)
class OOBSQLiInternalPayload(Payload):
    target_dbms: str = "Generic"

class OOB_SQLiModule(BaseOOBModule):
    def __init__(self, **kwargs):
        super().__init__("OOB SQL Injection", **kwargs)
        
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
        self.allow_redirects = False 

    def get_target_parameters(self, surface: Any, all_params: Iterable[str]) -> Iterable[str]:
        return list(all_params)
        
    def get_payload_count(self) -> int:
        base_payloads = get_oob_sqli_payloads(self.target_dbms)
        return len(base_payloads) * (self.evasion_level + 1)

    def get_payloads(self) -> Iterator[Payload]:
        """
        oob_sqli/payloads.py 에서 DBMS별로 필터링된 페이로드를 불러옵니다.
        """
        base_payloads = get_oob_sqli_payloads(self.target_dbms)
        
        for level in range(self.evasion_level + 1):
            for p in base_payloads:
                evaded_value = self._apply_evasion_by_level(p.value, level)
                
                yield OOBSQLiInternalPayload(
                    value=evaded_value,
                    attack_type=p.attack_type,
                    risk_level=p.risk_level,
                    target_dbms=getattr(p, 'target_dbms', 'Generic')
                )

    def _apply_evasion_by_level(self, value: str, level: int) -> str:
        if level == 0: 
            return value
        
        # Level 1: SQL 키워드 대소문자 변조
        if level >= 1:
            value = value.replace("SELECT", "sElEcT").replace("UNION", "uNiOn")\
                         .replace("AND", "aNd").replace("OR", "oR")\
                         .replace("CASE", "cAsE").replace("WHEN", "wHeN")
                         
        # Level 2: 공백을 주석 처리(/**/)로 우회
        if level >= 2:
            value = value.replace(" ", "/**/")
            
        # Level 3: 더블 URL 인코딩 및 Null Byte 삽입
        if level >= 3:
            value = value.replace("[OOB_HOST]", "OOB_HOST_PLACEHOLDER")
            value = urllib.parse.quote(urllib.parse.quote(value)) + "%00"
            value = value.replace("OOB_HOST_PLACEHOLDER", "[OOB_HOST]")
            
        return value