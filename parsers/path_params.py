"""URL 경로(Path) 파라미터 추출 — SPA API / REST 스타일."""

from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse

UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
OBJECT_ID_REGEX = re.compile(r"^[0-9a-fA-F]{24}$")
NUM_ID_REGEX = re.compile(r"^\d+$")
LONG_TOKEN_REGEX = re.compile(r"^[A-Za-z0-9_-]{32,}$")
PLACEHOLDER_IN_PATH = re.compile(r"\{(id|token)\}")


def _classify_segment(segment: str) -> str | None:
    """동적 세그먼트면 플레이스홀더 이름(id/token) 반환, 아니면 None."""
    if NUM_ID_REGEX.match(segment) or OBJECT_ID_REGEX.match(segment) or UUID_REGEX.match(segment):
        return "id"
    if LONG_TOKEN_REGEX.match(segment):
        return "token"
    return None


def normalize_path_segments(path: str) -> tuple[str, dict[str, str]]:
    """
    경로 세그먼트에서 동적 값을 {id}/{token} 플레이스홀더로 치환.
    반환: (template_path, {param_name: original_value})
    """
    if not path or path == "/":
        return path or "/", {}

    leading_slash = path.startswith("/")
    segments = [s for s in path.split("/") if s]
    params: dict[str, str] = {}
    template_parts: list[str] = []
    id_counter = 0

    for seg in segments:
        kind = _classify_segment(seg)
        if kind == "id":
            id_counter += 1
            key = "id" if id_counter == 1 else f"id{id_counter}"
            params[key] = seg
            template_parts.append("{id}")
        elif kind == "token":
            key = "token" if "token" not in params else f"token{id_counter}"
            params[key] = seg
            template_parts.append("{token}")
        else:
            template_parts.append(seg)

    if not params:
        return path, {}

    template_path = "/" + "/".join(template_parts)
    if not leading_slash and not path.startswith("/"):
        template_path = template_path.lstrip("/")
    return template_path, params


def extract_path_surface(url: str) -> tuple[str, dict[str, str], str] | None:
    """
  URL에서 path 파라미터 surface 후보 추출.
  반환: (template_url, path_parameters, http_method_hint) 또는 None
  http_method_hint는 호출측에서 덮어쓸 수 있음.
    """
    if not url or not url.startswith(("http://", "https://")):
        return None

    parsed = urlparse(url)
    template_path, params = normalize_path_segments(parsed.path)
    if not params:
        # 이미 {id} 형태의 템플릿 URL인 경우
        if PLACEHOLDER_IN_PATH.search(parsed.path):
            return None
        return None

    template_url = urlunparse(
        (parsed.scheme, parsed.netloc, template_path, parsed.params, "", parsed.fragment)
    )
    return template_url, params, "GET"


def extract_path_surface_from_template(
        template_url: str,
        original_url: str,
) -> tuple[str, dict[str, str]] | None:
    """정규화된 template URL과 원본 URL에서 path 파라미터 값 매핑."""
    if not PLACEHOLDER_IN_PATH.search(template_url):
        return None
    orig_parts = [p for p in urlparse(original_url).path.split("/") if p]
    tmpl_parts = [p for p in urlparse(template_url).path.split("/") if p]
    if len(orig_parts) != len(tmpl_parts):
        return extract_path_surface(original_url)[:2] if extract_path_surface(original_url) else None

    params: dict[str, str] = {}
    id_n = 0
    for orig, tmpl in zip(orig_parts, tmpl_parts):
        if tmpl == "{id}":
            id_n += 1
            key = "id" if id_n == 1 else f"id{id_n}"
            params[key] = orig
        elif tmpl == "{token}":
            key = "token" if "token" not in params else f"token_{id_n}"
            params[key] = orig
    if not params:
        return None
    return template_url, params
