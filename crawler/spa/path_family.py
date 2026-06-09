"""SPA/API path_key 간 body 필드 병합 범위 (범용 REST 리소스 트리)."""

from __future__ import annotations


def normalize_path_key(path: str) -> str:
    p = (path or "").strip()
    if not p.startswith("/"):
        p = "/" + p
    return p.rstrip("/").lower() or "/"


def api_resource_family_root(path_key: str) -> str:
    """
    형제 엔드포인트(confirm/process 등)끼리만 body 필드를 공유하는 리소스 루트.
    /api/checkout/confirm -> /api/checkout
    /api/board/write -> /api/board
    /profile/edit -> /profile
    """
    segments = [seg for seg in normalize_path_key(path_key).split("/") if seg]
    if not segments:
        return "/"
    if segments[0] == "api" and len(segments) >= 2:
        return f"/api/{segments[1]}"
    return f"/{segments[0]}"


def spa_path_keys_related(path_key: str, sample_key: str) -> bool:
    """클라이언트 라우트(/board/write)와 API 경로(/api/board/write) 샘플 연결."""
    if not path_key or not sample_key:
        return False

    api_norm = normalize_path_key(path_key)
    sample_norm = normalize_path_key(sample_key)
    if api_norm == sample_norm:
        return True

    if api_norm.startswith("/api/"):
        without_api = api_norm[4:]
        if without_api == sample_norm:
            return True
    if api_norm.endswith(sample_norm):
        if len(api_norm) == len(sample_norm):
            return True
        return api_norm[-len(sample_norm) - 1] == "/"
    return False


def path_keys_share_body_field_family(path_key: str, sample_key: str) -> bool:
    """
    서로 다른 API 리소스(/api/board vs /api/checkout) 전역 병합을 막고,
    같은 리소스 트리·SPA 라우트 쌍만 body 필드를 공유한다.
    """
    if spa_path_keys_related(path_key, sample_key):
        return True

    pk = normalize_path_key(path_key)
    sk = normalize_path_key(sample_key)
    if pk == sk:
        return True

    root_pk = api_resource_family_root(pk)
    root_sk = api_resource_family_root(sk)
    if root_pk != root_sk:
        return False

    if sk.startswith(pk + "/") or pk.startswith(sk + "/"):
        return True
    if pk == root_pk or sk == root_sk:
        return True
    return pk.startswith(root_pk + "/") and sk.startswith(root_sk + "/")
