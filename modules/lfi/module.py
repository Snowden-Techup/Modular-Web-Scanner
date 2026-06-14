import logging
from modules.base_module import BaseModule
from modules.lfi.analyzer import detect_lfi
from modules.lfi.payloads import generate_payloads

logger = logging.getLogger(__name__)

class LFIModule(BaseModule):
    def __init__(self, evasion_level: int = 1):
        super().__init__("LFI")
        self.evasion_level = evasion_level
        self._payloads: list | None = None

    def get_payloads(self):
        if self._payloads is None:
            self._payloads = generate_payloads(evasion_level=self.evasion_level)
        return self._payloads

    def analyze(self, response, payload, elapsed_time, original_res=None, requester=None) -> bool:
        is_vuln, evidences = detect_lfi(
            response=response,
            payload=payload,
            elapsed_time=elapsed_time,
        )
        return is_vuln
