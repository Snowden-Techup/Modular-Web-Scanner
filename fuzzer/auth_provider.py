"""퍼징 단계 인증 헤더/쿠키 주입 및 401 시 갱신."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Protocol

from crawler.auth_context import (
    AUTH_STORAGE_KEY_HINTS,
    build_auth_cookies_from_storage,
    build_auth_headers,
    log_auth_injection,
)
from crawler.session_manager import AuthConfig, SessionManager

# 흔한 세션/토큰 쿠키 이름 (부분 문자열 "session" 매칭은 하지 않음)
_EXACT_AUTH_COOKIE_NAMES = frozenset(
    {
        "phpsessid",
        "jsessionid",
        "asp.net_sessionid",
        "connect.sid",
        "sessionid",
        "sid",
        "token",
        "access_token",
        "accesstoken",
        "auth_token",
        "authtoken",
        "id_token",
        "jwt",
        "bearer",
        "authorization",
    }
)

MAX_AUTH_REFRESH_ATTEMPTS = 3


class AuthProvider(Protocol):
    async def apply(self, headers: dict[str, Any], cookies: dict[str, Any]) -> None: ...

    async def refresh(self) -> bool: ...

    def should_retry_on(self, status: int) -> bool: ...


def _normalize_cookie_name(name: str) -> str:
    return str(name).lower().replace("-", "_")


def _is_auth_cookie_name(name: str) -> bool:
    """
    인증 관련 쿠키 이름 판별.

    analytics_session 등 일반 쿠키는 제외하고, 알려진 세션/토큰 이름만 매칭한다.
    """
    norm = _normalize_cookie_name(name)
    if norm in _EXACT_AUTH_COOKIE_NAMES:
        return True
    return any(hint in norm for hint in AUTH_STORAGE_KEY_HINTS)


def strip_snapshot_auth(
    headers: dict[str, Any],
    cookies: dict[str, Any],
    *,
    provider_headers: dict[str, str],
    provider_cookies: dict[str, str],
) -> None:
    """
    provider가 실제로 덮어쓸 항목만 surface 스냅샷에서 제거.

    - Bearer만 있는 provider는 Authorization만 교체 (surface 쿠키 유지)
    - 멀티 유저/역할별 surface 토큰 테스트는 provider 미사용 시 스냅샷 유지
    """
    if provider_headers.get("Authorization"):
        for key in list(headers.keys()):
            if str(key).lower() == "authorization":
                del headers[key]

    if not provider_cookies:
        return

    for key in list(cookies.keys()):
        if key in provider_cookies or _is_auth_cookie_name(key):
            del cookies[key]


class ScanAuthProvider:
    """
    스캔 세션 단위 인증 상태.

    - local-storage / CLI 쿠키 / 로그인 재시도로 Bearer·세션 쿠키 유지
    - 401 응답 시 로그인에 성공한 경우에만 재로그인 후 1회 재시도
    """

    def __init__(
        self,
        *,
        auth_headers: dict[str, str] | None = None,
        auth_cookies: dict[str, str] | None = None,
        auth_config: AuthConfig | None = None,
        session_manager: SessionManager | None = None,
        refresh_on_status: tuple[int, ...] = (401,),
        max_refresh_attempts: int = MAX_AUTH_REFRESH_ATTEMPTS,
    ) -> None:
        self._headers = dict(auth_headers or {})
        self._cookies = dict(auth_cookies or {})
        self._auth_config = auth_config
        self._session_manager = session_manager
        self._refresh_on_status = refresh_on_status
        self._max_refresh_attempts = max(0, int(max_refresh_attempts))
        self._refresh_lock = asyncio.Lock()
        self._refresh_count = 0
        self._refresh_disabled = False

    @property
    def refresh_count(self) -> int:
        return self._refresh_count

    @property
    def can_refresh(self) -> bool:
        return (
            not self._refresh_disabled
            and self._session_manager is not None
            and self._auth_config is not None
            and self._refresh_count < self._max_refresh_attempts
        )

    def should_retry_on(self, status: int) -> bool:
        return status in self._refresh_on_status and self.can_refresh

    async def apply(self, headers: dict[str, Any], cookies: dict[str, Any]) -> None:
        strip_snapshot_auth(
            headers,
            cookies,
            provider_headers=self._headers,
            provider_cookies=self._cookies,
        )
        for key, value in self._headers.items():
            headers[key] = value
        for key, value in self._cookies.items():
            cookies[key] = value

    async def refresh(self) -> bool:
        if not self.can_refresh:
            return False

        async with self._refresh_lock:
            if not self.can_refresh:
                return False
            assert self._session_manager is not None
            assert self._auth_config is not None
            try:
                ok = await self._session_manager.login(self._auth_config)
            except Exception:
                self._refresh_disabled = True
                return False
            if not ok:
                self._refresh_disabled = True
                print(
                    f"[!] [Auth] refresh disabled after failed login: "
                    f"{self._auth_config.login_url}"
                )
                return False
            self._sync_from_session()
            self._refresh_count += 1
            print(
                f"[*] [Auth] session refreshed via login "
                f"({self._auth_config.login_url}, count={self._refresh_count})"
            )
            return True

    def _sync_from_session(self) -> None:
        if self._session_manager is None:
            return
        outbound = getattr(self._session_manager, "_headers", None) or {}
        auth_header = outbound.get("Authorization")
        if auth_header:
            self._headers["Authorization"] = str(auth_header)
        self._cookies.update(self._session_manager.get_cookies())


def collect_cookies_from_surfaces(surfaces: Any) -> dict[str, str]:
    """크롤 surface에 실린 세션 쿠키를 퍼징 단계에 전달."""
    merged: dict[str, str] = {}
    if not surfaces:
        return merged
    for surface in surfaces:
        raw = getattr(surface, "cookies", None) or {}
        if isinstance(raw, dict):
            for key, value in raw.items():
                if value is None:
                    continue
                key_str = str(key).strip()
                if key_str:
                    merged[key_str] = str(value)
    return merged


def merge_scan_cookies(args: Any, surfaces: Any = None) -> dict[str, str]:
    """CLI --cookie 와 크롤 surface 쿠키를 합친다 (surface 값 우선)."""
    from cli.options import parse_cookies

    cookies = parse_cookies(getattr(args, "cookie", "") or "")
    for key, value in collect_cookies_from_surfaces(surfaces).items():
        cookies[key] = value
    return cookies


def _has_session_cookie(cookies: dict[str, str]) -> bool:
    return any(_is_auth_cookie_name(name) for name in cookies)


def parse_local_storage_arg(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return {}
        try:
            data = json.loads(text)
            return dict(data) if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


async def create_scan_auth_provider(
    args: Any,
    *,
    base_cookies: dict[str, str] | None = None,
    surfaces: Any = None,
) -> ScanAuthProvider | None:
    """
    CLI/Web 인자로부터 퍼징용 AuthProvider 생성.

    정적 토큰(local-storage/쿠키) 또는 로그인 성공 시 provider 반환.
    로그인 실패 시 refresh 경로는 비활성화한다.
    """
    local_storage = parse_local_storage_arg(getattr(args, "local_storage", "{}"))
    auth_headers = build_auth_headers(local_storage)
    auth_cookies = dict(base_cookies or {})
    for name, value in build_auth_cookies_from_storage(local_storage).items():
        auth_cookies.setdefault(name, value)
    for name, value in collect_cookies_from_surfaces(surfaces).items():
        auth_cookies[name] = value

    crawl_mode = str(getattr(args, "crawl_mode", "hybrid") or "hybrid").lower()
    has_crawl_session = _has_session_cookie(auth_cookies)

    login_url = (getattr(args, "login_url", "") or "").strip()
    username = (getattr(args, "username", "") or "").strip()
    password = (getattr(args, "password", "") or "").strip()
    auth_config: AuthConfig | None = None
    session_manager: SessionManager | None = None

    if login_url and username and password:
        login_cfg = AuthConfig(
            login_url=login_url,
            username=username,
            password=password,
            username_field=getattr(args, "username_field", "username"),
            password_field=getattr(args, "password_field", "password"),
            csrf_token_name=getattr(args, "csrf_field", None) or None,
            submit_field=getattr(args, "submit_field", None) or None,
            login_body_format=getattr(args, "login_body_format", "auto"),
        )
        sm = SessionManager()
        if auth_cookies:
            sm.set_cookies(auth_cookies)
        try:
            await sm.create_session()
            if await sm.login(login_cfg):
                auth_config = login_cfg
                session_manager = sm
                outbound = getattr(sm, "_headers", None) or {}
                if outbound.get("Authorization"):
                    auth_headers["Authorization"] = str(outbound["Authorization"])
                auth_cookies.update(sm.get_cookies())
                print(f"[*] [Auth] fuzz-phase login succeeded: {login_url}")
            else:
                if crawl_mode == "dynamic" and has_crawl_session:
                    print(
                        f"[*] [Auth] fuzz-phase login failed for {login_url}; "
                        f"using crawl session cookie(s) from attack surfaces."
                    )
                else:
                    print(
                        f"[!] [Auth] fuzz-phase login failed: {login_url} "
                        f"(refresh disabled; using static tokens only if any)"
                    )
                await sm.close()
        except Exception as exc:
            print(f"[!] [Auth] fuzz-phase login error: {exc}")
            try:
                await sm.close()
            except Exception:
                pass

    if not auth_headers and not auth_cookies:
        return None

    log_auth_injection(local_storage, auth_headers, auth_cookies)
    return ScanAuthProvider(
        auth_headers=auth_headers,
        auth_cookies=auth_cookies,
        auth_config=auth_config,
        session_manager=session_manager,
    )


async def close_scan_auth_provider(provider: ScanAuthProvider | None) -> None:
    if provider is None:
        return
    session_manager = provider._session_manager
    if session_manager is not None:
        try:
            await session_manager.close()
        except Exception:
            pass


@asynccontextmanager
async def scan_auth_lifecycle(
    args: Any,
    *,
    base_cookies: dict[str, str] | None = None,
    surfaces: Any = None,
) -> AsyncIterator[ScanAuthProvider | None]:
    """
    CLI·Web 공통: provider 생성 → set_auth_provider → finally 정리.
    """
    from fuzzer.request_builder import set_auth_provider

    provider = await create_scan_auth_provider(
        args,
        base_cookies=base_cookies,
        surfaces=surfaces,
    )
    set_auth_provider(provider)
    try:
        yield provider
    finally:
        set_auth_provider(None)
        await close_scan_auth_provider(provider)
