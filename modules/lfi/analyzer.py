import logging
from urllib.parse import unquote
from modules.lfi.payloads import LFIPayload
from modules.lfi.signatures import LFI_ERROR_SIGNATURES, LFI_SIGNATURES
from fuzzer.runtime_config import clamp_text, get_fuzzer_runtime_config

logger = logging.getLogger(__name__)


def _lfi_analysis_text(response) -> str:
    cfg = get_fuzzer_runtime_config()
    cap = cfg.lfi.resolved_analyze_bytes(cfg.max_response_body_bytes)
    return clamp_text(getattr(response, "text", "") or "", cap)


def detect_lfi(response, payload, elapsed_time) -> tuple[bool, list[str]]:
    if not isinstance(payload, LFIPayload):
        return False, []

    evidences: list[str] = []
    res_text = _lfi_analysis_text(response)
    response_url = str(getattr(response, "url", "") or "")
    target_file = payload.expected_file

    # If request is redirected to login page, treat as non-vulnerable response.
    if "/login.php" in response_url.lower():
        return False, []

    # Signature-based detection for both file disclosure and wrapper/RCE outputs.
    signature = LFI_SIGNATURES.get(target_file)

    if signature and signature.search(res_text):
        evidences.append(f"[FileDisclosure] signature matched: {target_file}")

    # Error-based detection: require reflection evidence to reduce false positives.
    payload_value = getattr(payload, "value", "")
    unquoted_payload = unquote(payload_value) if payload_value else ""
    path_keyword = unquoted_payload.split("/")[-1] if unquoted_payload else ""
    if "resource=" in unquoted_payload:
        path_keyword = unquoted_payload.split("resource=")[-1]

    is_reflected = (
        (unquoted_payload and unquoted_payload in res_text)
        or (path_keyword and path_keyword in res_text)
        or (target_file and target_file in res_text)
    )

    if is_reflected:
        for error_signature in LFI_ERROR_SIGNATURES:
            if error_signature.search(res_text):
                evidences.append(
                    "[LFI_Error_Probable] error response with reflected path "
                    f"(keyword={path_keyword!r})"
                )
                break

    return (len(evidences) > 0), evidences