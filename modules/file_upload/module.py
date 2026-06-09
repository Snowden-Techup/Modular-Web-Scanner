from __future__ import annotations

from urllib.parse import urlsplit

from modules.base_module import BaseModule
from modules.file_upload.analyzer import detect_file_upload
from modules.file_upload.form_helpers import select_upload_target_parameters
from modules.file_upload.markers import VERIFY_TEMPLATE
from modules.file_upload.payloads import FilePayload, get_file_upload_payloads
from modules.file_upload.path_discovery import discover_verify_urls
from modules.file_upload.verifier import (
    build_verify_url_list,
    is_direct_upload_file_url,
    verify_upload_response,
)


class FileUploadModule(BaseModule):
    def __init__(self):
        super().__init__("File Upload")

    def get_payloads(self):
        return get_file_upload_payloads()

    def get_target_parameters(self, surface, parameters):
        """
        Run only where upload-like behavior is plausible.
        """
        method = str(getattr(getattr(surface, "method", ""), "value", surface.method)).upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return ()
        parameter_list = [str(param) for param in parameters]
        return select_upload_target_parameters(surface, parameter_list)

    def analyze(self, response, payload, elapsed_time, original_res=None, requester=None) -> bool:
        is_vuln, _ = detect_file_upload(response=response, payload=payload)
        return is_vuln

    async def verify(
        self,
        *,
        session,
        surface,
        parameter,
        payload,
        response,
        baseline_response=None,
    ) -> bool:
        """
        Stage-2 active verification:
        - RCE: marker present, interpreter tags stripped (PHP/JSP/…)
        - Static: malicious file content served verbatim from upload URL
        - Template: marker rendered on app routes (Node EJS overwrite)
        """
        if not isinstance(payload, FilePayload):
            return False

        split = urlsplit(surface.url)
        base = f"{split.scheme}://{split.netloc}"
        upload_text = getattr(response, "text", "") or ""
        headers = getattr(surface, "headers", None) or {}
        cookies = getattr(surface, "cookies", None) or {}
        source_url = getattr(surface, "source_url", None)

        verify_urls = await discover_verify_urls(
            session,
            base_url=base,
            filename=payload.filename,
            upload_response_text=upload_text,
            surface_url=str(surface.url),
            source_url=str(source_url) if source_url else None,
            payload=payload,
            headers=headers,
            cookies=cookies,
            surface=surface,
            upload_response=response,
        )

        if not verify_urls and (payload.verify_mode or "").lower() == VERIFY_TEMPLATE:
            verify_urls = build_verify_url_list(
                base_url=base,
                upload_response_text="",
                payload=payload,
                surface_url=str(surface.url),
                include_fallback=False,
            )

        if not verify_urls:
            return False

        request_kwargs = {}
        if headers:
            request_kwargs["headers"] = headers
        if cookies:
            request_kwargs["cookies"] = cookies

        for verify_url in verify_urls:
            try:
                async with session.get(verify_url, **request_kwargs) as verify_response:
                    body = await verify_response.text(errors="replace")
            except Exception:
                continue

            direct_file = is_direct_upload_file_url(verify_url, payload.filename)
            result = verify_upload_response(body, payload, direct_file=direct_file)
            if result.verified:
                return True

        return False
