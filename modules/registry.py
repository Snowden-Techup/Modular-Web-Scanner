from __future__ import annotations

from modules.base_module import BaseModule
from modules.bruteforce.module import BruteforceModule
from modules.lfi.module import LFIModule
from modules.file_upload.module import FileUploadModule
from modules.sqli.module import SQLiModule
from modules.osci.module import OSCiModule
from modules.ssrf.module import SSRFModule
from modules.stored_xss.module import StoredXSSModule
from modules.reflected_xss.module import ReflectedXSSModule
from modules.ssti.module import SSTIModule
from modules.oob_sqli.module import OOB_SQLiModule
from modules.oob_osci.module import OOB_OSCiModule

def get_attack_modules(attack_type: str) -> list[BaseModule]:
    """
    Module factory for CLI/runtime selection.
    Add new module mappings here as modules grow.
    """
    factories: dict[str, type[BaseModule]] = {
        "sqli": SQLiModule,
        "osci": OSCiModule,
        "bruteforce": BruteforceModule,
        "ssrf": SSRFModule,
        "lfi": LFIModule,
        "file_upload": FileUploadModule,
        "stored_xss": StoredXSSModule,
        "reflected_xss": ReflectedXSSModule,
        "ssti": SSTIModule,
        "oob_sqli": OOB_SQLiModule,
        "oob_osci": OOB_OSCiModule,

    }
    if attack_type == "all":
        return [
            factory()
            for name, factory in factories.items()
            if name != "bruteforce"
        ]
    factory = factories.get(attack_type)
    return [factory()] if factory else []
