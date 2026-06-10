from __future__ import annotations

import copy
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Literal

from modules.ssrf.module import SSRF_MODULE_REPORT_NAME

_SSRF_INTERNAL_CLASS = "SSRF-Internal"
_SSRF_OOB_CLASS = "SSRF-OOB"
_OOB_OSCI_CLASS = "OSCi-OOB"
_OOB_SQLI_CLASS = "SQLi-OOB"
_BRUTEFORCE_CLASS = "Bruteforce"
_STORED_XSS_CLASS = "stored_xss"
_REFLECTED_XSS_CLASS = "Reflected XSS"
_RXSS_MODULE_NAME = "rxss"

# Consolidated File Upload report classes (group 12+ fixed + Bypass_* variants).
_FILE_UPLOAD_WEBSHELL = "FileUpload-Webshell"
_FILE_UPLOAD_STORED_XSS = "FileUpload-StoredXSS"
_FILE_UPLOAD_PATH_TRAVERSAL = "FileUpload-PathTraversal"
_FILE_UPLOAD_TEMPLATE = "FileUpload-TemplateInjection"

_SQLI_REPORT_TYPES = frozenset(
    {"SQLi-error_based", "SQLi-boolean_blind", "SQLi-time_blind"}
)
_LFI_REPORT_TYPES = frozenset(
    {
        "LFI_Basic_Linux",
        "LFI_Basic_Windows",
        "LFI_PHP_Wrapper",
        "LFI_RCE_Wrapper",
    }
)

# SSRF payload attack_type values (config/payloads/ssrf/*). Used when module/ssrf_channel
# are missing from flat DB rows so bypass_ipv6, file_read, etc. still group as SSRF-Internal.
_SSRF_ATTACK_TYPES = frozenset(
    {
        "basic",
        "bypass_cidr",
        "bypass_decimal",
        "bypass_domain",
        "bypass_encoding",
        "bypass_ipv6",
        "bypass_ipv6_hostname",
        "bypass_octal",
        "bypass_rare",
        "bypass_unicode",
        "cloud_api",
        "cloud_bypass",
        "cloud_metadata",
        "cloud_redirect",
        "cloud_runtime",
        "dns_rebinding",
        "docker_api",
        "file_read",
        "http_probe",
        "jar_scheme",
        "k8s_etcd",
        "oob_candidate",
        "parser_confusion",
        "php_filter_bypass",
        "protocol_smuggling",
        "rancher_metadata",
        "redirect_bypass",
        "time_blind",
        "upgrade_to_xss",
        "verify_probe",
    }
)


def severity_rank(raw: str) -> int:
    """Lower is more severe (critical first)."""
    key = str(raw or "").strip().lower()
    if key in ("critical", "crit"):
        return 0
    if key == "high":
        return 1
    if key in ("medium", "med"):
        return 2
    if key == "low":
        return 3
    return 4


# Evasion / encoding variants of the same logical attack (group under one finding).
_MUTATION_TYPE_SUFFIXES: tuple[str, ...] = (
    "_Double_Encoded",
    "_URL_Encoded",
    "_Null_Byte",
    "_Path_Bypass_1",
    "_Path_Bypass_2",
    "_Case_Bypass",
    "_path_encode",
    "_ip_decimal",
    "_ip_hex",
)


def canonical_attack_type_for_grouping(raw: str) -> str:
    """Strip known mutation suffixes so e.g. LFI_PHP_Wrapper_URL_Encoded -> LFI_PHP_Wrapper."""
    original = str(raw or "")
    s = original
    changed = True
    while changed:
        changed = False
        for suf in _MUTATION_TYPE_SUFFIXES:
            if s.endswith(suf):
                s = s[: -len(suf)]
                changed = True
                break
    return s if s else original


def _module_name(record: dict[str, Any]) -> str:
    return str(record.get("module") or "").strip()


def _raw_attack_type(record: dict[str, Any]) -> str:
    attack = record.get("attack_info") or {}
    return str(attack.get("type") or "").strip()


def _canonical_ssrf_attack_base(record: dict[str, Any]) -> str:
    return canonical_attack_type_for_grouping(_raw_attack_type(record))


def _is_ssrf_by_attack_type(record: dict[str, Any]) -> bool:
    return _canonical_ssrf_attack_base(record) in _SSRF_ATTACK_TYPES


def _is_ssrf_record(record: dict[str, Any]) -> bool:
    return _module_name(record) == SSRF_MODULE_REPORT_NAME or _is_ssrf_by_attack_type(record)


def _is_oob_ssrf_record(record: dict[str, Any]) -> bool:
    if record.get("ssrf_channel") == "oob":
        return True
    # OOB-only payload labels when channel metadata was not persisted (e.g. flat DB rows).
    return _canonical_ssrf_attack_base(record) in {"upgrade_to_xss", "cloud_redirect"}


def _is_inband_ssrf_record(record: dict[str, Any]) -> bool:
    if _is_oob_ssrf_record(record):
        return False
    if record.get("ssrf_channel") == "inband":
        return True
    return _is_ssrf_record(record)


def _ssrf_report_type(record: dict[str, Any]) -> str:
    if _is_oob_ssrf_record(record):
        return _SSRF_OOB_CLASS
    return _SSRF_INTERNAL_CLASS


def _file_upload_report_type(raw_type: str) -> str:
    base = canonical_attack_type_for_grouping(raw_type)
    if base.startswith("Bypass_"):
        return _FILE_UPLOAD_WEBSHELL
    if base in {"Stored_XSS_SVG", "Stored_XSS_HTML"}:
        return _FILE_UPLOAD_STORED_XSS
    if base == "Path_Traversal_File_Write":
        return _FILE_UPLOAD_PATH_TRAVERSAL
    if base == "Template_Overwrite_EJS":
        return _FILE_UPLOAD_TEMPLATE
    if base.startswith("Magic_Byte") or base in {
        "Null_Byte_Injection_PHP",
        "Double_Extension_PHP",
    }:
        return _FILE_UPLOAD_WEBSHELL
    return _FILE_UPLOAD_WEBSHELL


def _osci_report_type(raw_type: str) -> str:
    normalized = raw_type.lower().replace("-", "_")
    if "time" in normalized:
        return "OSCi-time_based"
    return "OSCi-in_band"


def _is_reflected_xss_record(record: dict[str, Any]) -> bool:
    if _module_name(record) == _RXSS_MODULE_NAME:
        return True
    raw = _raw_attack_type(record).lower()
    return raw == "reflected xss" or raw.startswith("reflected_xss")


def report_attack_type(record: dict[str, Any]) -> str:
    """
    Canonical ``attack_info.type`` for scan_report.json grouping and display.
    """
    module = _module_name(record)
    raw_type = _raw_attack_type(record)
    base_type = canonical_attack_type_for_grouping(raw_type)

    if _is_ssrf_record(record):
        return _ssrf_report_type(record)

    if module == "OOB OS Command Injection":
        return _OOB_OSCI_CLASS

    if module == "OOB SQL Injection":
        return _OOB_SQLI_CLASS

    if module == "OS Command Injection":
        return _osci_report_type(raw_type)

    if base_type.lower() == "oob":
        return _OOB_OSCI_CLASS

    if module == "Brute Force" or base_type.startswith("BF-"):
        return _BRUTEFORCE_CLASS

    if module == "stored_xss" or base_type.lower() == _STORED_XSS_CLASS:
        return _STORED_XSS_CLASS

    if _is_reflected_xss_record(record) or base_type.lower().startswith("reflected_xss"):
        return _REFLECTED_XSS_CLASS

    if module == "File Upload":
        return _file_upload_report_type(raw_type)

    if base_type in _SQLI_REPORT_TYPES or base_type.startswith("SQLi-"):
        if base_type in _SQLI_REPORT_TYPES:
            return base_type
        lowered = base_type.lower()
        if "error" in lowered:
            return "SQLi-error_based"
        if "boolean" in lowered:
            return "SQLi-boolean_blind"
        if "time" in lowered:
            return "SQLi-time_blind"

    if base_type in _LFI_REPORT_TYPES:
        return base_type

    if raw_type in {"in-band", "time-based"}:
        return _osci_report_type(raw_type)

    if base_type.startswith("BF-"):
        return _BRUTEFORCE_CLASS

    return base_type or raw_type or "Unknown"


def grouping_attack_class(record: dict[str, Any]) -> str:
    """Logical attack class for dedupe keys (collapsed report types)."""
    return report_attack_type(record)


def presentation_for_vulnerability_record(record: dict[str, Any]) -> dict[str, Any]:
    """Apply consolidated report labels after dedupe."""
    out = copy.deepcopy(record)
    attack = out.setdefault("attack_info", {})
    original = str(attack.get("type") or "")
    report_type = report_attack_type(out)
    if report_type:
        attack["type"] = report_type
    if original and report_type and original != report_type:
        attack["attack_variant"] = original
        if _is_ssrf_record(out) or _is_ssrf_by_attack_type(out):
            attack["ssrf_variant"] = original
    return out


def vulnerability_group_key(record: dict[str, Any]) -> tuple[str, str, str, str, str]:
    """
    Group by URL, HTTP method, parameter placement, parameter name, and attack class.

    Uses consolidated report types (``report_attack_type``), e.g. in-band SSRF ->
    ``SSRF-Internal``, OOB SSRF -> ``SSRF-OOB``, File Upload bypass variants ->
    ``FileUpload-Webshell``.
    """
    target = record.get("target") or {}
    return (
        str(target.get("url") or ""),
        str(target.get("method") or ""),
        str(target.get("location") or ""),
        str(target.get("parameter") or ""),
        grouping_attack_class(record),
    )


def vulnerability_sort_key(record: dict[str, Any]) -> tuple[int, str, str]:
    attack = record.get("attack_info") or {}
    target = record.get("target") or {}
    return (
        severity_rank(str(attack.get("severity") or "high")),
        str(target.get("url") or ""),
        str(target.get("parameter") or ""),
    )


def dedupe_vulnerabilities(
    records: list[dict[str, Any]],
    *,
    mode: Literal["first_in_order", "best_evidence"] = "first_in_order",
) -> list[dict[str, Any]]:
    """
    Collapse records that share the same group key to a single entry (one PoC).

    - first_in_order: keep the first record per key (scan / discovery order).
    - best_evidence: for each key, pick the lowest severity rank, then shortest
      payload string, then earliest index in the input list (for offline JSON).
    """
    if mode == "first_in_order":
        seen: set[tuple[str, str, str, str, str]] = set()
        out: list[dict[str, Any]] = []
        for rec in records:
            key = vulnerability_group_key(rec)
            if key in seen:
                continue
            seen.add(key)
            out.append(presentation_for_vulnerability_record(rec))
        return out

    buckets: dict[tuple[str, str, str, str, str], list[tuple[int, dict[str, Any]]]] = (
        defaultdict(list)
    )
    for index, rec in enumerate(records):
        buckets[vulnerability_group_key(rec)].append((index, rec))

    picked: list[dict[str, Any]] = []
    for _key, items in sorted(buckets.items(), key=lambda kv: kv[0]):
        def score(item: tuple[int, dict[str, Any]]) -> tuple[int, int, int]:
            idx, rec = item
            attack = rec.get("attack_info") or {}
            payload = str(attack.get("payload_value") or "")
            return (severity_rank(str(attack.get("severity") or "high")), len(payload), idx)

        picked.append(min(items, key=score)[1])
    return [presentation_for_vulnerability_record(r) for r in picked]


def dedupe_report_document(
    report: dict[str, Any],
    *,
    mode: Literal["first_in_order", "best_evidence"] = "best_evidence",
) -> dict[str, Any]:
    """Return a deep-copied report with vulnerabilities deduped and summary updated."""
    data = copy.deepcopy(report)
    vulns = list(data.get("vulnerabilities") or [])
    raw_count = len(vulns)
    deduped = dedupe_vulnerabilities(vulns, mode=mode)
    deduped_sorted = sorted(deduped, key=vulnerability_sort_key)
    data["vulnerabilities"] = deduped_sorted
    meta = data.setdefault("metadata", {})
    summary = meta.setdefault("summary", {})
    summary["findings"] = len(deduped_sorted)
    summary["findings_raw"] = raw_count
    return data


def full_report_path(output_path: str | Path) -> Path:
    """scan_report.json -> scan_report_full.json"""
    p = Path(output_path)
    return p.with_name(f"{p.stem}_full{p.suffix}")


_SQLI_GUIDE = (
    "모든 동적 데이터베이스 조회 연산 수행 시 f-string 문자열 조립을 전면 금지하고 파라미터 바인딩 기반의 "
    "PreparedStatement를 고정 적용하십시오. 웹 애플리케이션용 DB 접속 계정에서 DDL(CREATE, ALTER, DROP 등) "
    "권한을 거세하고, JPA/Hibernate 등 ORM 프레임워크 활용 시에도 Native Query 작성 시 내부 문자열 결합이 "
    "유발되지 않도록 주의해야 합니다."
)
_OSCI_GUIDE = (
    "시스템 운영체제 명령어 실행 쉘을 개방하는 os.system, popen 함수 또는 subprocess의 shell=True 설정을 "
    "엄격히 금지하십시오. 가급적 언어 내장 API나 안전한 프레임워크 함수로 로직을 교체하고, 외부 인자 주입이 "
    "불가피하다면 정규표현식을 적용한 화이트리스트 방식으로 입력값을 사전 정제하여 Argument Injection 우회 "
    "구문까지 원천 차단해야 합니다."
)
_LFI_GUIDE = (
    "외부에서 전달되는 문자열을 파일 I/O 시스템 경로 스트림에 즉시 바인딩하지 마십시오. 불가피하게 물리 경로를 "
    "조립해야 하는 상황이라면 입력값 내 Null Byte 문자(\\x00, %00)를 검증 후 하드 기각하고, realpath() 및 "
    "abspath() 함수를 통해 경로를 정규화한 뒤 os.path.commonpath()를 활용해 타깃 자원이 사전에 약속된 "
    "화이트리스트 디렉토리 Prefix의 내부 경로 구조를 절대 이탈하지 않는지 이중 검증해야 합니다."
)
_SSRF_GUIDE = (
    "요청 대상 호스트 도메인을 DNS Resolution 처리하여 변환된 실제 IP 주소가 사설망 대역(RFC 1918 범위: "
    "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/12, 127.0.0.0/8 등) 및 링크 로컬 대역에 수렴하는지 철저히 "
    "화이트리스트 필터링하십시오. 특히 검증 단계와 실제 커넥션을 맺는 실행 단계의 시간 차이를 유도해 목적지를 "
    "변조하는 DNS Rebinding 공격을 원천 봉쇄하기 위해, DNS 조회가 완료된 IP 주소로 통신 주소 자체를 하드 "
    "고정(IP Pinning)하여 요청을 생성하고, 원래의 도메인 텍스트는 HTTP Host 헤더 필드에 명시적으로 주입하는 "
    "규칙을 구현하십시오."
)
_FILE_UPLOAD_GUIDE = (
    "클라이언트 요청 프레임에서 전송되어 조작이 지극히 간단한 Content-Type(MIME) 헤더 검증에만 절대 단독 "
    "의존하지 마십시오. 대소문자를 통합 관리하는 엄격한 확장자 화이트리스트 체계를 구성함과 동시에, 바이너리 "
    "도입부를 정밀 대조하는 파일 시그니처(Magic Number) 검증 엔진을 교차 수행하십시오. 업로드 파일명은 UUID "
    "등의 난수로 전면 대치하여 웹 루트 외부의 별도 독립 스토리지에 격리 저장하고 실행 권한을 완벽 박탈해야 "
    "합니다. 이미지 업로드 인터페이스의 경우, 이미지 구조 내부에 악성 페이로드가 난독화되어 내장되는 공격을 "
    "완전 소멸시키기 위해 백엔드 레벨에서 그래픽 라이브러리를 통한 재인코딩(Re-encoding) 연산을 필수 "
    "통과시키십시오."
)
_STORED_XSS_GUIDE = (
    "사용자 측에서 주입되는 원시 입력값을 정제 처리 없이 영구 저장소에 보관하거나 그대로 클라이언트 응답 화면에 "
    "출력하지 마십시오. 데이터가 출력되어 브라우저에 의해 해석되는 컨텍스트 경계면에서 HTML 엔티티 인코딩 연산 "
    "(< → &lt;, > → &gt;, \" → &quot;, ' → &#x27;, & → &amp;)을 전역적으로 강제 적용해야 합니다. "
    "프레임워크가 제공하는 기본 자동 이스케이프(Auto-escaping) 파이프라인의 규격을 준수하고, 원시 입력을 "
    "무가공 상태로 출력하는 기능의 사용을 지양하며 최상위 계층에 콘텐츠 보안 정책(CSP) 헤더를 보강하십시오."
)
_REFLECTED_XSS_GUIDE = (
    "HTTP 요청 아웃풋 스트림(GET 파라미터, POST 폼 필드 등)에 바인딩되는 모든 변동 인자는 유효성 교정 처리를 "
    "거치지 않았다면 브라우저 응답 본문에 즉시 에코(Echo) 형태로 재출력하지 마십시오. 최종 렌더링 단계 직전에 "
    "HTML 엔티티 인코딩을 예외 없이 강제화하고, HTTP 응답 헤더 필드에 X-Content-Type-Options: nosniff 정책을 "
    "선언하여 브라우저 환경이 임의의 악성 MIME 스니핑 가정을 수립해 구문을 해석하는 행위를 원천 제어해야 합니다."
)
_BRUTEFORCE_GUIDE = (
    "로그인 연산 실패 시 반환되는 예외 문구가 계정의 실제 실재 유무를 해커가 판별하여 열거(User Enumeration)하는 "
    "힌트로 악용되지 않도록, 실패 원인과 무관하게 통일되고 완전 표준화된 예외 메시지(\"아이디 또는 비밀번호가 "
    "올바르지 않습니다.\")만을 대외 인터페이스에 출력하십시오. 임계값을 제어하기 위해 클라이언트 IP 대역 및 "
    "타깃 로그인 ID 식별 코드 기준의 다중 계층 처리율 제한(Rate Limiting) 방어 모델을 도입하고, 비정상적인 "
    "로그 흐름을 모니터링하여 이상 감지 시 멀티 팩터 인증(MFA) 또는 CAPTCHA 시스템을 트리거해야 합니다."
)
_SSTI_GUIDE = (
    "사용자 입력값을 템플릿 소스 문자열에 직접 결합하거나 render/evaluate 계열 API에 원시 문자열로 전달하지 "
    "마십시오. f-string, format(), String.format(), 템플릿 리터럴 등으로 동적 템플릿 본문을 조립하는 패턴을 "
    "금지하고, 정적 템플릿 파일과 데이터 컨텍스트를 분리하여 프레임워크가 제공하는 안전한 변수 바인딩 "
    "(Jinja2 render(context), Thymeleaf Model, Razor ViewData 등)만 사용하십시오. Jinja2·Twig·Freemarker 등 "
    "서버 템플릿 엔진을 사용할 때는 샌드박스 모드와 autoescape를 활성화하고, __import__, eval, exec, "
    "os/system 등 위험 빌트인·헬퍼에 대한 접근을 엔진 설정 또는 정책으로 차단해야 합니다. 사용자 입력이 "
    "템플릿 문법({{ }}, ${ }, <% %>, #{ } 등)을 포함할 수 있는 경우, 템플릿 렌더링 전 HTML 엔티티 인코딩 "
    "또는 허용 문자 화이트리스트 검증을 적용하고, 불가피한 동적 콘텐츠 조합이 필요하다면 템플릿 엔진 대신 "
    "순수 문자열 치환 없는 로직 레이어에서 안전하게 조립하십시오."
)

_OOB_GUIDE = (
    "아웃바운드 HTTP/DNS 요청이 외부 서버에서 확인된 경우, 서버 측 코드가 사용자 입력값을 "
    "검증 없이 네트워크 요청의 목적지로 사용하고 있음을 의미합니다. "
    "요청 대상 URL/호스트를 엄격한 화이트리스트 기반으로 검증하고, DNS Resolution 후 "
    "반환된 IP 주소가 사설망(RFC 1918) 및 링크 로컬 대역에 속하는지 이중 확인하십시오. "
    "OS 커맨드 인젝션이 원인인 경우, 외부 인자를 셸 명령에 직접 전달하는 구조를 제거하고 "
    "언어 내장 API로 교체한 뒤 화이트리스트 입력 정제를 적용해야 합니다."
)
_OOB_REF = (
    "OWASP Top 10:2021 A10:Server-Side Request Forgery / CWE-918 "
    "(보조 매핑: CWE-78 OS Command Injection)"
)

_SQLI_REF = "OWASP Top 10:2021 A03:Injection / CWE-89"
_OSCI_REF = "OWASP Top 10:2021 A03:Injection / CWE-78"
_LFI_REF = "OWASP Top 10:2021 A01:Broken Access Control / CWE-22"
_SSRF_REF = "OWASP Top 10:2021 A10:Server-Side Request Forgery / CWE-918"
_FILEUPLOAD_REF = "OWASP Top 10:2021 A04:Insecure Design / CWE-434"
_XSS_REF = "OWASP Top 10:2021 A03:Injection / CWE-79"
_BRUTEFORCE_REF = "OWASP Top 10:2021 A07:Identification and Authentication Failures / CWE-307"
_SSTI_REF = "OWASP Top 10:2021 A03:Injection / CWE-1336 (Server-Side Template Injection)"

SECURE_CODING_DB: dict[str, dict[str, str]] = {
    "OOB-Callback": {"reference": _OOB_REF, "secure_coding_guide": _OOB_GUIDE},
    "OOB-SSRF": {"reference": _OOB_REF, "secure_coding_guide": _OOB_GUIDE},
    "OOB-OSCI-curl": {"reference": _OOB_REF, "secure_coding_guide": _OOB_GUIDE},
    "OOB-OSCI-wget": {"reference": _OOB_REF, "secure_coding_guide": _OOB_GUIDE},
    "OOB-OSCI-win-curl": {"reference": _OOB_REF, "secure_coding_guide": _OOB_GUIDE},
    "OOB-Generic": {"reference": _OOB_REF, "secure_coding_guide": _OOB_GUIDE},
    "SQLi": {"reference": _SQLI_REF, "secure_coding_guide": _SQLI_GUIDE},
    "SQLi-error_based": {"reference": _SQLI_REF, "secure_coding_guide": _SQLI_GUIDE},
    "SQLi-boolean_blind": {"reference": _SQLI_REF, "secure_coding_guide": _SQLI_GUIDE},
    "SQLi-time_blind": {"reference": _SQLI_REF, "secure_coding_guide": _SQLI_GUIDE},
    "OSCi": {"reference": _OSCI_REF, "secure_coding_guide": _OSCI_GUIDE},
    "OSCi-in_band": {"reference": _OSCI_REF, "secure_coding_guide": _OSCI_GUIDE},
    "OSCi-time_based": {"reference": _OSCI_REF, "secure_coding_guide": _OSCI_GUIDE},
    "LFI": {"reference": _LFI_REF, "secure_coding_guide": _LFI_GUIDE},
    "LFI_Basic_Linux": {"reference": _LFI_REF, "secure_coding_guide": _LFI_GUIDE},
    "LFI_Basic_Windows": {"reference": _LFI_REF, "secure_coding_guide": _LFI_GUIDE},
    "LFI_PHP_Wrapper": {"reference": _LFI_REF, "secure_coding_guide": _LFI_GUIDE},
    "LFI_RCE_Wrapper": {
        "reference": f"{_LFI_REF} (보조 매핑: CWE-94 Code Injection)",
        "secure_coding_guide": _LFI_GUIDE,
    },
    "SSRF": {"reference": _SSRF_REF, "secure_coding_guide": _SSRF_GUIDE},
    "SSRF-Internal": {"reference": _SSRF_REF, "secure_coding_guide": _SSRF_GUIDE},
    "SSRF-OOB": {"reference": _SSRF_REF, "secure_coding_guide": _SSRF_GUIDE},
    "File Upload": {"reference": _FILEUPLOAD_REF, "secure_coding_guide": _FILE_UPLOAD_GUIDE},
    "FileUpload-Webshell": {"reference": _FILEUPLOAD_REF, "secure_coding_guide": _FILE_UPLOAD_GUIDE},
    "FileUpload-StoredXSS": {
        "reference": f"{_FILEUPLOAD_REF} (보조 매핑: OWASP A03 / CWE-79 Cross-Site Scripting)",
        "secure_coding_guide": _FILE_UPLOAD_GUIDE,
    },
    "FileUpload-PathTraversal": {
        "reference": "OWASP Top 10:2021 A01:Broken Access Control / CWE-22 (Path Traversal)",
        "secure_coding_guide": _FILE_UPLOAD_GUIDE,
    },
    "FileUpload-TemplateInjection": {
        "reference": f"{_FILEUPLOAD_REF} (보조 매핑: CWE-1336 Server-Side Template Injection / CWE-94)",
        "secure_coding_guide": _FILE_UPLOAD_GUIDE,
    },
    "stored_xss": {"reference": _XSS_REF, "secure_coding_guide": _STORED_XSS_GUIDE},
    "Stored XSS": {"reference": _XSS_REF, "secure_coding_guide": _STORED_XSS_GUIDE},
    "Reflected XSS": {"reference": _XSS_REF, "secure_coding_guide": _REFLECTED_XSS_GUIDE},
    "Bruteforce": {"reference": _BRUTEFORCE_REF, "secure_coding_guide": _BRUTEFORCE_GUIDE},
    "SSTI": {"reference": _SSTI_REF, "secure_coding_guide": _SSTI_GUIDE},
}


def get_attack_guidance(attack_type: str) -> dict[str, str]:
    """Return reference mapping and secure coding guide for the given attack type."""
    key = str(attack_type or "").strip()
    if key in SECURE_CODING_DB:
        return SECURE_CODING_DB[key]
    if key.lower() == "ssti" or key.startswith("ssti:"):
        return {"reference": _SSTI_REF, "secure_coding_guide": _SSTI_GUIDE}
    return {}
