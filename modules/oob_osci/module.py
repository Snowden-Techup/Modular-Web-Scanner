import urllib.parse
import dataclasses
from typing import Iterator, Any, Iterable
from modules.base_oob_module import BaseOOBModule
from modules.oob_osci.payload import get_oob_osci_payloads
from core.models import Payload

@dataclasses.dataclass(frozen=True, slots=True)
class OOBOSCiInternalPayload(Payload):
    target_os: str = "Unix"
    action_level: str = "SHELL"

class OOB_OSCiModule(BaseOOBModule):
    def __init__(self, **kwargs):
        super().__init__("OOB OS Command Injection", **kwargs)
        
        # CLI 입력 매핑 (linux -> Unix, window -> Windows, all -> all)
        raw_os = kwargs.get('target_os', 'linux').lower()
        if raw_os == 'windows' or raw_os == 'window':
            self.target_os = "Windows"
        elif raw_os == 'all':
            self.target_os = "all"
        else:
            self.target_os = "Unix"

        self.evasion_level = kwargs.get('evasion_level', 0)
        self.allow_redirects = False 

    def get_target_parameters(self, surface: Any, all_params: Iterable[str]) -> Iterable[str]:
        return list(all_params)

    def get_payload_count(self) -> int:
        base_payloads = get_oob_osci_payloads(self.target_os)
        return len(base_payloads) * (self.evasion_level + 1)

    def get_payloads(self) -> Iterator[Payload]:
        base_payloads = get_oob_osci_payloads(self.target_os)
        
        for level in range(self.evasion_level + 1):
            for p in base_payloads:
                evaded_value = self._apply_evasion_by_level(p.value, level, p.target_os, p.action_level)
                
                yield OOBOSCiInternalPayload(
                    value=evaded_value,
                    attack_type=p.attack_type,
                    risk_level=p.risk_level,
                    target_os=p.target_os,
                    action_level=p.action_level
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
        
        # Level 2: 키워드 난독화 (OOB 주력 명령어 추가)
        if level >= 2:
            if t_os == "Unix":
                value = value.replace("echo", "ec\\ho")
                value = value.replace("curl", "c\\url")
                value = value.replace("wget", "w\\get")
            else:
                value = value.replace("echo", "ec^ho")
                value = value.replace("curl", "c^url")
                value = value.replace("ping", "p^ing")
                if "PS" in action_level:
                    value = value.replace("Invoke-WebRequest", "I'nvoke-W'ebRequest")
                    value = value.replace("Resolve-DnsName", "R'esolve-D'nsName")
        
        # Level 3: URL 인코딩
        if level >= 3:
            value = value.replace("[OOB_HOST]", "OOB_HOST_PLACEHOLDER")
            value = urllib.parse.quote(value)
            value = value.replace("OOB_HOST_PLACEHOLDER", "[OOB_HOST]")
        
        return value