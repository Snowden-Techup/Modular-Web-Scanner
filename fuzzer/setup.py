from __future__ import annotations

from core import AttackSurface
from fuzzer.engine import FuzzerEngine
from modules.bruteforce.module import BruteforceModule
from modules.lfi.module import LFIModule
from modules.file_upload.module import FileUploadModule
from modules.sqli.module import SQLiModule
from modules.osci.module import OSCiModule
from modules.ssrf.module import SSRFModule
from modules.stored_xss.module import StoredXSSModule
from modules.reflected_xss.module import ReflectedXSSModule
from modules.ssti.module import SSTIModule
from modules.oob.client import DEFAULT_OAST_SERVER_URL, OASTClient, normalize_oast_server_url
from modules.oob.module import OOBModule
from modules.oob_osci.module import OOB_OSCiModule
from modules.oob_sqli.module import OOB_SQLiModule

ALL_PIPELINE_MODULE_TYPES = [
    "sqli",
    "osci",
    "lfi",
    "file_upload",
    "ssrf",
    "stored_xss",
    "reflected_xss",
]


def select_modules(args) -> list:
    selected = []

    current_scan_id = getattr(args, "scan_id", "ERROR_SCAN_ID_NOT_PASSED")

    if args.type in ("sqli", "all"):
        sqli_module = SQLiModule(
            include_time_based=args.sqli_time_based,
            max_time_payloads=args.sqli_time_max,
            evasion_level=args.sqli_evasion_level,
            target_dbms=args.target_dbms,
        )
        selected.append(sqli_module)

    if args.type in ("oob_sqli", "all"):
        oob_sqli_module = OOB_SQLiModule(
            target_dbms=args.target_dbms,
            evasion_level=args.sqli_evasion_level,
            scan_id=current_scan_id,
            oob_domain=getattr(args, "oob_domain", "oob.snowden.kr"),
            redis_url=getattr(args, "redis_url", "redis://localhost:6379/0"),
        )
        selected.append(oob_sqli_module)

    if args.type in ("osci", "all"):
        osci_module = OSCiModule(
            include_time_based=args.osci_time_based,
            max_time_payloads=args.osci_time_max,
            evasion_level=args.osci_evasion_level,
            target_os=args.target_os,
        )
        selected.append(osci_module)

    if args.type in ("oob_osci", "all"):
        oob_osci_module = OOB_OSCiModule(
            target_os=args.target_os,
            evasion_level=args.osci_evasion_level,
            scan_id=current_scan_id,
            oob_domain=getattr(args, "oob_domain", "oob.snowden.kr"),
            redis_url=getattr(args, "redis_url", "redis://localhost:6379/0"),
        )
        selected.append(oob_osci_module)

    if args.type == "bruteforce":
        bruteforce_module = BruteforceModule(
            wordlist_path=args.bf_wordlist,
            enable_mutation=not args.bf_disable_mutation,
            mutation_level=args.bf_mutation_level,
            enable_true_bruteforce=args.bf_true_random,
            bf_charset=args.bf_charset,
            bf_min_length=args.bf_min_length,
            bf_max_length=args.bf_max_length,
            max_dictionary_candidates=args.bf_max_dictionary,
            max_true_bf_candidates=args.bf_max_true_random,
            stop_on_first_hit=args.bf_stop_on_first_hit,
            username_param=args.bf_username_param,
            bf_username=args.bf_username,
            bf_target_param=args.bf_target_param,
        )
        selected.append(bruteforce_module)

    if args.type in ("lfi", "all"):
        selected.append(LFIModule(evasion_level=args.lfi_evasion_level))

    if args.type in ("file_upload", "all"):
        selected.append(FileUploadModule())

    if args.type in ("ssrf", "all"):
        selected.append(
            SSRFModule(
                include_oob_templates=args.ssrf_oob,
                bypass_level=args.ssrf_evasion_level,
            )
        )
        
    if args.type in ("stored_xss", "all"):
        sxss_categories = getattr(args, "sxss_categories", None) or []
        sxss_target_params = getattr(args, "sxss_target_params", None) or []
        selected.append(
            StoredXSSModule(
                bypass_level=getattr(args, "sxss_evasion_level", 1),
                scan_mode=getattr(args, "sxss_scan_mode", "full"),
                max_risk_level=getattr(args, "sxss_max_risk_level", "Critical"),
                categories=sxss_categories if sxss_categories else None,
                target_params=sxss_target_params if sxss_target_params else None,
            )
        )
        
    if args.type in ("reflected_xss", "all"):
        selected.append(
            ReflectedXSSModule(
                evasion_level=args.rxss_evasion_level
            )
        )
    if args.type in ("ssti", "all"):
        selected.append(
            SSTIModule(
                evasion_level=getattr(args, "ssti_evasion_level", 0),
                max_payloads=getattr(args, "ssti_max_payloads", None),
            )
        )  

    if args.type == "oob":
        oast_server = normalize_oast_server_url(getattr(args, "oob_server", "") or "")
        oast_client = OASTClient(
            oast_server,
            poll_retries=getattr(args, "oob_retries", 3),
            poll_delay=getattr(args, "oob_poll_delay", 5.0),
            poll_timeout=getattr(args, "oob_poll_timeout", 10.0),
        )
        selected.append(OOBModule(oast_client=oast_client))
        print(f"[*] OAST server: {oast_server}")

    return selected


def _module_runtime_payload_count(module) -> int:
    """실제 실행 목록 기준(변형·필터 포함). get_payload_count()와 다를 수 있음."""
    if hasattr(module, "get_payloads"):
        payloads = module.get_payloads()
        try:
            return len(payloads)
        except TypeError:
            # SQLi 등 Iterator 반환 모듈은 len() 불가 → get_payload_count() 사용
            pass
    if hasattr(module, "get_payload_count"):
        return module.get_payload_count()
    return 0


def count_module_payloads(modules: list) -> int:
    return sum(_module_runtime_payload_count(m) for m in modules)


def estimate_total_requests(surfaces: list[AttackSurface], modules: list) -> int:

    # 각 모듈의 실제 페이로드 개수(변형 포함)를 미리 계산
    module_payload_counts = {id(m): _module_runtime_payload_count(m) for m in modules}
    
    total = 0
    for surface in surfaces:
        # Engine submit path uses _iter_parameters (dynamic CSRF tokens excluded).
        all_params = tuple(FuzzerEngine._iter_parameters(surface))
        for module in modules:
            module_params = all_params
            selector = getattr(module, "get_target_parameters", None)
            
            if callable(selector):
                selected = selector(surface, all_params)
                module_params = tuple(selected) if selected is not None else ()
            
            total += len(module_params) * module_payload_counts[id(module)]
            
    return total