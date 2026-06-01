"""공격 표면(URL) 품질 필터 — 범용 노이즈·인증 엔드포인트 제거."""

from __future__ import annotations

import re
from urllib.parse import urlparse

# 로그인·회원가입·토큰 발급 등 — 일반 모듈 퍼징 제외 (브루트포스는 별도)
_AUTH_PATH_MARKERS: tuple[str, ...] = (
    "/login",
    "/logon",
    "/signin",
    "/sign-in",
    "/logout",
    "/signout",
    "/sign-out",
    "/register",
    "/signup",
    "/sign-up",
    "/oauth",
    "/authenticate",
    "/forgot-password",
    "/reset-password",
    "/wp-login",
    "/session/new",
)

# 경로가 인증 관련일 때 함께 있으면 제외할 파라미터 (credential 필드)
_AUTH_CREDENTIAL_PARAMS = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "pwd",
        "otp",
        "pin",
        "passcode",
    }
)

# 합성/캡처 API 중 퍼징 가치가 낮은 URL (범용)
_LOW_VALUE_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    # WebSocket / Real-time transport (퍼징 대상이 아님)
    re.compile(r"/socket\.io/?", re.IGNORECASE),
    re.compile(r"/sockjs/?", re.IGNORECASE),
    re.compile(r"/engine\.io/?", re.IGNORECASE),
    re.compile(r"/ws/?", re.IGNORECASE),
    re.compile(r"/websocket/?", re.IGNORECASE),
    re.compile(r"/wss/?", re.IGNORECASE),
    # 정적 자산 디렉토리
    re.compile(r"/assets/", re.IGNORECASE),
    re.compile(r"/static/", re.IGNORECASE),
    re.compile(r"/_next/static/", re.IGNORECASE),
    re.compile(r"/_nuxt/", re.IGNORECASE),
    # i18n / locale 파일
    re.compile(r"\.i18n\.", re.IGNORECASE),
    re.compile(r"/i18n/", re.IGNORECASE),
    re.compile(r"/locales?/", re.IGNORECASE),
    # 기타 메타 파일
    re.compile(r"/favicon\.ico", re.IGNORECASE),
    re.compile(r"/robots\.txt$", re.IGNORECASE),
    re.compile(r"/sitemap\.xml$", re.IGNORECASE),
    re.compile(r"/manifest\.(?:json|webmanifest)$", re.IGNORECASE),
    # 정적 자산 확장자 (path 또는 query 시작 직전까지)
    re.compile(
        r"\.(?:css|js|mjs|map|woff2?|ttf|eot|otf|svg|png|jpe?g|gif|webp|ico|bmp|avif|"
        r"mp3|mp4|webm|ogg|wav|pdf|zip|tar|gz)(?:\?|$)",
        re.IGNORECASE,
    ),
)

# locale 번역 JSON 등 (path가 정확히 이 suffix로 끝나는 경우만 차단)
_LOW_VALUE_PATH_SUFFIXES = (
    "/en.json",
    "/ko.json",
    "/de.json",
    "/ja.json",
    "/zh.json",
    "/fr.json",
    "/es.json",
)


def is_low_value_fuzz_url(url: str) -> bool:
    """퍼징·스캔 가치가 낮은 URL (정적 자산, WebSocket, i18n 등)."""
    if not url:
        return True
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    path_query = f"{parsed.path}?{parsed.query}"
    for pattern in _LOW_VALUE_PATH_PATTERNS:
        if pattern.search(path_query):
            return True

    path_lower = (parsed.path or "").lower()
    for suffix in _LOW_VALUE_PATH_SUFFIXES:
        if path_lower.endswith(suffix):
            return True

    return False


def _normalize_path(url: str) -> str:
    try:
        return (urlparse(url).path or "/").rstrip("/").lower() or "/"
    except Exception:
        return "/"


def _path_matches_marker(path: str, marker: str) -> bool:
    marker = marker.lower().rstrip("/")
    if not marker:
        return False
    if path == marker:
        return True
    return path.endswith(marker) or f"{marker}/" in f"{path}/"


def _matches_login_url(surface_url: str, login_url: str) -> bool:
    login_url = (login_url or "").strip()
    if not login_url:
        return False
    try:
        surf = urlparse(surface_url)
        login = urlparse(login_url)
    except Exception:
        return False
    if surf.netloc and login.netloc and surf.netloc != login.netloc:
        return False
    surf_path = (surf.path or "/").rstrip("/").lower()
    login_path = (login.path or "/").rstrip("/").lower()
    if not login_path:
        return False
    return surf_path == login_path or surf_path.startswith(f"{login_path}/")


def is_auth_fuzz_surface(
    url: str,
    parameters: dict | None = None,
    *,
    login_urls: tuple[str, ...] = (),
    extra_path_markers: tuple[str, ...] = (),
) -> bool:
    """
    로그인·세션 발급 등 인증 전용 엔드포인트 여부.

    기본 제외 대상 (--fuzz-auth / bruteforce 모드에서만 포함 권장).
    """
    if not url:
        return False

    for login_url in login_urls:
        if _matches_login_url(url, login_url):
            return True

    path = _normalize_path(url)
    markers = _AUTH_PATH_MARKERS + tuple(extra_path_markers)
    if any(_path_matches_marker(path, marker) for marker in markers):
        return True

    if path.endswith("/token") or "/token/" in f"{path}/":
        return True

    params = parameters or {}
    if not params:
        return False

    param_names = {str(key).lower() for key in params.keys()}
    if not (param_names & _AUTH_CREDENTIAL_PARAMS):
        return False

    soft_markers = (
        "/login",
        "/signin",
        "/sign-in",
        "/logon",
        "/auth",
        "/account",
        "/user",
        "/session",
    )
    return any(_path_matches_marker(path, marker) for marker in soft_markers)
