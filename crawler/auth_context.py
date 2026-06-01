"""크롤러·SPA 공통 인증 헤더/쿠키 병합."""

from __future__ import annotations

from typing import Any

AUTH_STORAGE_KEY_HINTS = (
    "token",
    "access_token",
    "accesstoken",
    "jwt",
    "auth_token",
    "authtoken",
    "id_token",
    "bearer",
    "authorization",
)


def build_auth_headers(local_storage: dict[str, Any]) -> dict[str, str]:
    for key, raw_value in local_storage.items():
        if not raw_value or str(key).startswith("session:"):
            continue
        if not any(hint in str(key).lower() for hint in AUTH_STORAGE_KEY_HINTS):
            continue
        value = str(raw_value).strip()
        if len(value) < 8:
            continue
        if value.lower().startswith("bearer "):
            return {"Authorization": value}
        return {"Authorization": f"Bearer {value}"}
    return {}


def build_auth_cookies_from_storage(local_storage: dict[str, Any]) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for key, raw_value in local_storage.items():
        if not raw_value or str(key).startswith("session:"):
            continue
        key_str = str(key)
        if not any(hint in key_str.lower() for hint in AUTH_STORAGE_KEY_HINTS):
            continue
        value = str(raw_value).strip()
        if len(value) >= 8:
            cookies[key_str] = value
    return cookies


def log_auth_injection(
    local_storage: dict[str, Any],
    headers: dict[str, str],
    cookies: dict[str, str],
) -> None:
    keys = [k for k in local_storage if not str(k).startswith("session:")]
    if keys:
        print(f"[*] local-storage keys loaded: {', '.join(keys)}")
    if headers.get("Authorization"):
        preview = headers["Authorization"]
        if len(preview) > 28:
            preview = preview[:28] + "..."
        print(f"[*] Auth header set: {preview}")
    else:
        print("[!] No Authorization header from local-storage (login may be required).")
    if cookies.get("token") or cookies.get("accessToken") or cookies.get("access_token"):
        print("[*] Auth cookie mirrored from storage (token/accessToken).")
    elif keys:
        print("[!] No token cookie mirrored; some SPAs require both header and cookie.")


def build_page_auth_context(
    local_storage: dict[str, Any],
    *,
    extra_headers: dict[str, str] | None = None,
    base_cookies: dict[str, str] | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    headers = dict(extra_headers or {})
    headers.update(build_auth_headers(local_storage))
    cookies = dict(base_cookies or {})
    for name, value in build_auth_cookies_from_storage(local_storage).items():
        cookies.setdefault(name, value)
    return headers, cookies
