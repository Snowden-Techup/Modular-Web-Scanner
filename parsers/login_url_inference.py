"""SPA/REST 로그인 URL 추론 — 페이지 라우트(/login)와 API(/api/login) 분리."""

from __future__ import annotations

from urllib.parse import urljoin, urlparse, urlunparse


def iter_login_post_urls(login_url: str) -> list[str]:
    """
    JSON/폼 로그인 POST에 시도할 URL 후보 (중복 제거, 페이지 URL 우선).

    - ``/login`` 페이지 → ``/api/login`` API (Express·Vue·React SPA 공통)
    - 이미 ``/api/login`` 이면 그대로
  """
    raw = (login_url or "").strip()
    if not raw:
        return []

    parsed = urlparse(raw)
    if not parsed.scheme or not parsed.netloc:
        return [raw]

    ordered: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        u = (url or "").strip()
        if u and u not in seen:
            seen.add(u)
            ordered.append(u)

    add(raw)

    path = (parsed.path or "").rstrip("/") or "/"
    lower = path.lower()

    if lower.endswith("/login") or lower == "/login":
        stem = path[: -len("/login")] if lower.endswith("/login") else ""
        api_path = f"{stem}/api/login" if stem else "/api/login"
        add(urlunparse((parsed.scheme, parsed.netloc, api_path, "", "", "")))

    if "/api/" not in lower and lower not in ("/login",):
        add(urljoin(raw, "/api/login"))

    signin_variants = ("/signin", "/sign-in", "/auth/login")
    for suffix in signin_variants:
        if lower.endswith(suffix):
            base = path[: -len(suffix)]
            add(urlunparse((parsed.scheme, parsed.netloc, f"{base}/api/login", "", "", "")))
            break

    return ordered
