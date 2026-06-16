import logging
from urllib.parse import unquote
from modules.lfi.payloads import LFIPayload
from modules.lfi.signatures import LFI_ERROR_SIGNATURES, LFI_SIGNATURES

logger = logging.getLogger(__name__)

# Wrapper/RCE payloads must show PHP/RCE output — generic file errors are not proof.
_WRAPPER_EXPECTED_FILES = frozenset({"php_base64", "php_rot13", "rce_output"})

# PHP wrapper resource= targets — too common in HTML/JSON to count as path reflection.
_WEAK_RESOURCE_KEYWORDS = frozenset({
    "index",
    "index.php",
    "config",
    "config.php",
    "login",
    "login.php",
    "admin",
    "admin.php",
    "db",
    "db.php",
    "main",
    "main.php",
})


def _response_status(response) -> int:
    try:
        return int(getattr(response, "status", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _path_reflected_in_body(res_text: str, unquoted_payload: str, path_keyword: str) -> bool:
    """Strict reflection check for error-based LFI (avoids generic 'index' page text)."""
    if unquoted_payload and unquoted_payload in res_text:
        return True

    if not path_keyword:
        return False

    keyword = path_keyword.strip()
    lower = keyword.lower()
    if lower in _WEAK_RESOURCE_KEYWORDS:
        return False

    # Meaningful path segments (e.g. includes/config.php, ..%2f..%2fetc%2fpasswd)
    if len(keyword) >= 10 or "/" in keyword or "\\" in keyword or ".." in keyword:
        return keyword in res_text

    return False


def detect_lfi(response, payload, elapsed_time) -> tuple[bool, list[str]]:
    if not isinstance(payload, LFIPayload):
        return False, []

    evidences: list[str] = []
    status = _response_status(response)
    if status <= 0:
        return False, []

    res_text = getattr(response, "text", "") or ""
    response_url = str(getattr(response, "url", "") or "")
    target_file = payload.expected_file

    # If request is redirected to login page, treat as non-vulnerable response.
    if "/login.php" in response_url.lower():
        return False, []

    # Signature-based detection for file disclosure and wrapper/RCE outputs.
    signature = LFI_SIGNATURES.get(target_file)

    if signature and signature.search(res_text):
        evidences.append(f"[FileDisclosure] signature matched: {target_file}")

    # PHP/RCE wrappers: only signature hits count (Node ENOENT + "index" is not LFI).
    if target_file in _WRAPPER_EXPECTED_FILES:
        return (len(evidences) > 0), evidences

    # Error-based detection: require strong reflection evidence to reduce false positives.
    payload_value = getattr(payload, "value", "")
    unquoted_payload = unquote(payload_value) if payload_value else ""
    path_keyword = unquoted_payload.split("/")[-1] if unquoted_payload else ""
    if "resource=" in unquoted_payload:
        path_keyword = unquoted_payload.split("resource=")[-1]

    if _path_reflected_in_body(res_text, unquoted_payload, path_keyword):
        for error_signature in LFI_ERROR_SIGNATURES:
            if error_signature.search(res_text):
                evidences.append(
                    "[LFI_Error_Probable] error response with reflected path "
                    f"(keyword={path_keyword!r})"
                )
                break

    return (len(evidences) > 0), evidences
