from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

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
from modules.oob_osci.module import OOB_OSCiModule
from modules.oob_sqli.module import OOB_SQLiModule

# (module_type, accepted args.type values, factory)
_ModuleDef = tuple[str, tuple[str, ...], Callable[[Any], Any]]


def _oob_mode() -> str:
    is_saas_mode = os.getenv("CELERY_WORKER") == "1"
    return "webhook" if is_saas_mode else "polling"


def _oob_module_kwargs(args) -> dict:
    return {
        "scan_id": getattr(args, "scan_id", "ERROR_SCAN_ID_NOT_PASSED"),
        "oob_domain": getattr(args, "oob_domain", None) or os.getenv("OOB_DOMAIN", "oob.snowden.kr"),
        "redis_url": getattr(args, "redis_url", None) or os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        "oob_mode": _oob_mode(),
    }


def _module_defs(args) -> list[_ModuleDef]:
    """
    `-t all` 파이프라인 순서 = 아래 목록 순서 (웹 UI 공격 모듈 드롭다운과 동일, bruteforce 제외).
    새 모듈 추가 시 이 목록에 한 줄만 추가하면 select_modules / pipeline 모두 반영된다.
    """
    oob_kwargs = _oob_module_kwargs(args)
    return [
        (
            "sqli",
            ("sqli", "all"),
            lambda: SQLiModule(
                include_time_based=args.sqli_time_based,
                max_time_payloads=args.sqli_time_max,
                evasion_level=args.sqli_evasion_level,
                target_dbms=args.target_dbms,
            ),
        ),
        (
            "osci",
            ("osci", "all"),
            lambda: OSCiModule(
                include_time_based=args.osci_time_based,
                max_time_payloads=args.osci_time_max,
                evasion_level=args.osci_evasion_level,
                target_os=args.target_os,
            ),
        ),
        (
            "oob_sqli",
            ("oob_sqli", "all"),
            lambda: OOB_SQLiModule(
                target_dbms=args.target_dbms,
                evasion_level=args.sqli_evasion_level,
                **oob_kwargs,
            ),
        ),
        (
            "oob_osci",
            ("oob_osci", "all"),
            lambda: OOB_OSCiModule(
                target_os=args.target_os,
                evasion_level=args.osci_evasion_level,
                **oob_kwargs,
            ),
        ),
        (
            "lfi",
            ("lfi", "all"),
            lambda: LFIModule(evasion_level=args.lfi_evasion_level),
        ),
        (
            "file_upload",
            ("file_upload", "all"),
            lambda: FileUploadModule(),
        ),
        (
            "ssrf",
            ("ssrf", "all"),
            lambda: SSRFModule(
                include_oob_templates=args.ssrf_oob,
                bypass_level=args.ssrf_evasion_level,
            ),
        ),
        (
            "stored_xss",
            ("stored_xss", "all"),
            lambda: StoredXSSModule(
                bypass_level=getattr(args, "sxss_evasion_level", 1),
                scan_mode=getattr(args, "sxss_scan_mode", "full"),
                max_risk_level=getattr(args, "sxss_max_risk_level", "Critical"),
                categories=(getattr(args, "sxss_categories", None) or []) or None,
                target_params=(getattr(args, "sxss_target_params", None) or []) or None,
            ),
        ),
        (
            "reflected_xss",
            ("reflected_xss", "all"),
            lambda: ReflectedXSSModule(
                evasion_level=args.rxss_evasion_level,
            ),
        ),
        (
            "ssti",
            ("ssti", "all"),
            lambda: SSTIModule(
                evasion_level=getattr(args, "ssti_evasion_level", 0),
                max_payloads=getattr(args, "ssti_max_payloads", None),
            ),
        ),
    ]


def pipeline_module_types(args) -> list[str]:
    """`-t all` 순차 실행 대상. `_module_defs()`에서 `"all"` 포함 항목을 자동 추출."""
    return [module_type for module_type, accepted, _ in _module_defs(args) if "all" in accepted]


def select_modules(args) -> list:
    selected = [
        build()
        for _module_type, accepted, build in _module_defs(args)
        if args.type in accepted
    ]

    if args.type == "bruteforce":
        selected.append(
            BruteforceModule(
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
        )

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
