# core/surface_builder.py

import hashlib
import json
import logging
import asyncio
from typing import Callable, Awaitable, Set, List, Union, Dict, Any
from urllib.parse import urlparse, urlunparse

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_PLACEHOLDER_VALUES = frozenset({"test", "fuzz"})

from bs4 import BeautifulSoup

from core.models import PageData, AttackSurface, HttpMethod, ParamLocation
from parsers import form_extractor, link_extractor
from parsers import path_params
from parsers.param_inference import merge_inferred_query_params
from parsers.surface_filter import is_auth_fuzz_surface, is_low_value_fuzz_url

logger = logging.getLogger(__name__)

SurfaceCallback = Callable[[AttackSurface], Union[Awaitable[None], None]]


def _is_json_content_type(content_type: str) -> bool:
    """application/json; charset=utf-8 등 MIME 파라미터가 붙은 경우도 JSON으로 처리."""
    base = content_type.lower().split(";", 1)[0].strip()
    return base in ("application/json", "application/graphql") or base.endswith("+json")


def _is_form_content_type(content_type: str) -> bool:
    base = content_type.lower().split(";", 1)[0].strip()
    return base in ("application/x-www-form-urlencoded", "multipart/form-data")


class SurfaceBuilder:
    """
    공격 표면 빌더
    - 중복 파싱 방지 (Soup 재사용)
    - 동적 토큰(CSRF 등) 자동 병합
    - URL 쿼리스트링 중복 제거 및 파라미터 타입 평탄화 (Fuzzer 호환성)
    - 퍼저 콜백 직송
    - [추가] 큐 소비(Consumer) 로직 통합
    """

    def __init__(
            self,
            fuzzer_callback: SurfaceCallback,
            *,
            skip_csrf_surfaces: bool = True,
            skip_auth_surfaces: bool = True,
            login_urls: tuple[str, ...] = (),
            exclude_auth_paths: tuple[str, ...] = (),
    ):
        self.fuzzer_callback = fuzzer_callback
        self.skip_csrf_surfaces = skip_csrf_surfaces  # True=CSRF surface 제외 (기본)
        self.skip_auth_surfaces = skip_auth_surfaces
        self._login_urls = tuple(u.strip() for u in login_urls if (u or "").strip())
        self._exclude_auth_paths = tuple(
            p.strip() for p in exclude_auth_paths if (p or "").strip()
        )
        self._seen_signatures: Set[str] = set()
        self._skipped_csrf_count = 0
        self._auth_surfaces_skipped = 0
        self._path_surfaces_found = 0
        self._low_value_surfaces_skipped = 0

    async def consume_from_queue(self, queue_manager):
        """
        ✨ [신규] 큐에서 데이터를 직접 꺼내서 처리하는 Consumer 역할 수행
        Sentinel(None) 신호를 받으면 큐에 남은 데이터를 모두 처리하고 안전하게 종료됩니다.
        """
        logger.info("[SurfaceBuilder] 큐 데이터 소비 루프를 시작합니다.")
        while True:
            # 큐에서 데이터를 가져옴 (데이터가 올 때까지 비동기 대기)
            page_data = await queue_manager.get_page()

            # 엔진이 보낸 종료 신호(None) 확인
            if page_data is None:
                logger.info("[SurfaceBuilder] 모든 데이터 처리가 완료되어 컨슈머를 종료합니다.")
                break

            try:
                await self.process_page(page_data)
            except Exception as exc:
                page_url = getattr(page_data, "url", "unknown")
                logger.exception(
                    "[SurfaceBuilder] Page processing failed (url=%s): %s",
                    page_url,
                    exc,
                )

    @staticmethod
    def _generate_signature(surface: AttackSurface) -> str:
        """AttackSurface의 고유 해시 생성 (중복 제거용)"""
        param_keys = str(sorted(surface.parameters.keys()))
        raw = f"{surface.url}:{surface.method.value}:{surface.param_location.value}:{param_keys}"
        return hashlib.md5(raw.encode()).hexdigest()

    @staticmethod
    def _strip_query_string(url: str) -> str:
        """✅ [수정] URL에서 쿼리스트링(?id=1)을 제거하여 중복 결합 방지"""
        parsed = urlparse(url)
        # scheme, netloc, path, params, query(제거), fragment
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, '', parsed.fragment))

    @staticmethod
    def _parse_graphql_arg_types(raw: str) -> dict[str, str]:
        if not raw:
            return {}
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
        except (json.JSONDecodeError, TypeError):
            pass
        return {}

    @staticmethod
    def _parse_dict_attr(raw: str) -> dict[str, str]:
        if not raw:
            return {}
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
        except (json.JSONDecodeError, TypeError):
            pass
        return {}

    @staticmethod
    def _surface_path_key(url: str) -> str:
        try:
            return (urlparse(url).path or "/").rstrip("/").lower() or "/"
        except Exception:
            return "/"

    @staticmethod
    def _canonical_surface_path(path: str) -> str:
        """
        /api 접두사 차이에서 발생하는 SPA 중복을 하나로 묶기 위한 경로 정규화.
        예) /orders/view, /api/orders/view -> /orders/view
        """
        normalized = (path or "/").rstrip("/").lower() or "/"
        if normalized == "/api":
            return "/"
        if normalized.startswith("/api/"):
            trimmed = normalized[4:]
            return trimmed if trimmed else "/"
        return normalized

    @classmethod
    def _surface_group_key(cls, surface: AttackSurface) -> str:
        method = str(getattr(surface.method, "value", surface.method)).upper()
        location = str(getattr(surface.param_location, "value", surface.param_location))
        path = cls._surface_path_key(surface.url)
        canonical_path = cls._canonical_surface_path(path)
        param_keys = ",".join(sorted(str(k).strip().lower() for k in (surface.parameters or {}).keys()))
        return f"{method}:{location}:{canonical_path}:{param_keys}"

    @staticmethod
    def _is_api_path(url: str) -> bool:
        path = (urlparse(url).path or "/").lower()
        return path == "/api" or path.startswith("/api/")

    @staticmethod
    def _is_json_like_surface(surface: AttackSurface) -> bool:
        content_type = str(surface.content_type or "").lower()
        if _is_json_content_type(content_type):
            return True
        for value in (surface.headers or {}).values():
            if _is_json_content_type(str(value)):
                return True
        return False

    @classmethod
    def _surface_richness_score(cls, surface: AttackSurface) -> tuple[int, int, int, int]:
        method = str(getattr(surface.method, "value", surface.method)).upper()
        method_rank = 4 if method in _MUTATING_METHODS else 1
        json_bonus = 1 if cls._is_json_like_surface(surface) else 0
        api_bonus = 1 if cls._is_api_path(surface.url) else 0
        params = dict(surface.parameters or {})
        non_empty = sum(
            1 for value in params.values()
            if str(value).strip() and str(value).strip().lower() not in _PLACEHOLDER_VALUES
        )
        placeholder_only = bool(params) and non_empty == 0
        desc = str(surface.description or "").lower()
        inferred_penalty = 1 if "inferred:true" in desc else 0
        return (
            method_rank,
            json_bonus,
            api_bonus,
            non_empty,
            -int(placeholder_only),
            -inferred_penalty,
        )

    @classmethod
    def _dedupe_surfaces(cls, surfaces: List[AttackSurface]) -> List[AttackSurface]:
        """Prefer richer surfaces in the same logical endpoint group."""
        buckets: dict[str, list[AttackSurface]] = {}
        for surface in surfaces:
            key = cls._surface_group_key(surface)
            buckets.setdefault(key, []).append(surface)

        kept: list[AttackSurface] = []
        for group in buckets.values():
            if len(group) == 1:
                kept.append(group[0])
                continue
            mutating = [
                s for s in group
                if str(getattr(s.method, "value", s.method)).upper() in _MUTATING_METHODS
            ]
            if mutating:
                kept.append(max(mutating, key=cls._surface_richness_score))
                continue
            kept.append(max(group, key=cls._surface_richness_score))
        return kept

    @staticmethod  # ✨ [수정] 중복 데코레이터 제거
    def _normalize_parameters(raw_params: Dict[str, Any]) -> Dict[str, str]:
        """✨ [원복] 모든 파라미터를 단일 문자열로 평탄화 (리스트는 첫 번째 값만 유지)"""
        normalized = {}
        for key, value in raw_params.items():
            if isinstance(value, list):
                # 리스트인 경우 첫 번째 값만 취함
                normalized[key] = str(value[0]) if value else ""
            else:
                normalized[key] = str(value)
        return normalized

    @staticmethod
    def _build_parameter_confidence(
            params: Dict[str, Any],
            *,
            default_level: str = "high",
            inferred_keys: set[str] | None = None,
    ) -> Dict[str, str]:
        """
        Build per-parameter confidence labels for generic scan prioritization.
        - high: observed from real requests/forms
        - medium: mixed/derived from runtime context
        - low: purely inferred/seeded
        """
        confidence: Dict[str, str] = {}
        inferred = inferred_keys or set()
        for key in params.keys():
            key_str = str(key).strip()
            if not key_str:
                continue
            confidence[key_str] = "low" if key_str in inferred else default_level
        return confidence

    @staticmethod
    def _resolve_param_location(method: HttpMethod, form: Dict[str, Any]) -> ParamLocation:
        """
        SPA 합성 form은 GET이면 항상 query, 비-GET API는 기본적으로 JSON 본문으로 본다.
        일반 HTML form은 form enctype/content-type 힌트를 존중한다.
        """
        if method == HttpMethod.GET:
            return ParamLocation.QUERY

        content_type = str(form.get("data_content_type", "")).lower()
        if _is_json_content_type(content_type):
            return ParamLocation.BODY_JSON
        if _is_form_content_type(content_type):
            return ParamLocation.BODY_FORM

        has_spa_metadata = bool(form.get("data_orig_method") or content_type)
        if has_spa_metadata and method in (
            HttpMethod.POST,
            HttpMethod.PUT,
            HttpMethod.PATCH,
            HttpMethod.DELETE,
        ):
            return ParamLocation.BODY_JSON

        if method in (HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH):
            return ParamLocation.BODY_FORM
        return ParamLocation.QUERY

    def _extract_surfaces_sync(self, page_data: PageData) -> List[AttackSurface]:
        """
        ✨ [핵심 수정] CPU를 집중적으로 사용하는 동기식 데이터 추출 및 정제 로직
        이 메서드는 메인 이벤트 루프를 막지 않기 위해 별도의 스레드에서 실행됩니다.
        """
        surfaces: List[AttackSurface] = []

        # CrawlerEngine에서 만든 soup이 있으면 재사용, 없으면 1회만 파싱
        if isinstance(page_data.soup, BeautifulSoup):
            source_soup = page_data.soup
        else:
            source_soup = BeautifulSoup(page_data.html, 'html.parser')

        # ==========================================
        # 1. HTML Form 기반 AttackSurface 추출
        # ==========================================
        forms = form_extractor.extract_forms(source_soup, base_url=page_data.url)

        for form in forms:
            #  원본 HTTP 메서드 복원
            orig_method = form.get('data_orig_method')
            method_str = str(orig_method).upper() if orig_method else str(form.get('method', 'GET')).upper()

            try:
                method = HttpMethod(method_str)
            except ValueError:
                method = HttpMethod.GET

            loc = self._resolve_param_location(method, form)

            action_url = str(form.get('action')) if form.get('action') else str(page_data.url)
            safe_url = self._strip_query_string(action_url) if loc == ParamLocation.QUERY else action_url

            normalized_params = self._normalize_parameters(form.get('parameters', {}))
            inferred_params = False
            if loc == ParamLocation.QUERY and not normalized_params:
                normalized_params = merge_inferred_query_params(safe_url, normalized_params)
                inferred_params = bool(normalized_params)
            parameters: dict[str, Any] = dict(normalized_params)
            inferred_keys: set[str] = set(normalized_params.keys()) if inferred_params else set()

            if page_data.dynamic_tokens:
                parameters.update(page_data.dynamic_tokens)
            confidence = self._build_parameter_confidence(
                parameters,
                default_level="high",
                inferred_keys=inferred_keys,
            )
            if page_data.dynamic_tokens:
                for token_name in page_data.dynamic_tokens.keys():
                    token_key = str(token_name).strip()
                    if token_key:
                        confidence[token_key] = "medium"

            # GraphQL 메타데이터를 Description을 통해 우회 전달
            gql_type = form.get('data_graphql_type')
            gql_op = form.get('data_graphql_op')

            desc = f"Form (risk: {form.get('risk_level')}, tokens: {len(page_data.dynamic_tokens)})"
            if inferred_params:
                desc += " inferred:true"
            if gql_type and gql_op:
                desc = f"GraphQL:{gql_type}:{gql_op}"  # Fuzzer가 파싱할 수 있는 규격

            gql_arg_types = self._parse_graphql_arg_types(
                str(form.get("data_graphql_arg_types", ""))
            )

            # Prefer synthesized provenance when provided (SPA synthesized HTML).
            form_source_url = str(
                form.get("data_source_url")
                or form.get("data_route_context")
                or ""
            ).strip()
            source_url = form_source_url if form_source_url else str(page_data.url)
            depth_hint = 0
            try:
                depth_hint = int(form.get("data_depth") or 0)
            except Exception:
                depth_hint = 0
            response_headers = self._parse_dict_attr(str(form.get("data_response_headers") or ""))
            server_info = self._parse_dict_attr(str(form.get("data_server_info") or ""))
            response_content_type = str(form.get("data_response_content_type") or "").strip()
            if not response_headers and response_content_type:
                response_headers = {"content-type": response_content_type}

            surfaces.append(AttackSurface(
                url=safe_url,
                method=method,
                param_location=loc,
                parameters=parameters,
                headers=response_headers if response_headers else page_data.headers,
                cookies=page_data.cookies,
                dynamic_tokens=page_data.dynamic_tokens.copy(),
                server_info=server_info if server_info else page_data.server_info.copy(),
                source_url=source_url,
                description=desc,
                depth=depth_hint or getattr(page_data, "depth", 0) or 0,
                content_type=response_content_type or None,
                graphql_arg_types=gql_arg_types,
                parameter_confidence=confidence,
            ))

        # ==========================================
        # 2. URL 파라미터(Link) 기반 AttackSurface 추출
        # ==========================================
        links = link_extractor.extract_links(source_soup, base_url=page_data.url)

        for link in links:
            if not link.get('params'): continue

            method_str = str(link.get('method', 'GET')).upper()
            try:
                method = HttpMethod(method_str)
            except ValueError:
                method = HttpMethod.GET

            # ✅ URL 쿼리스트링 제거 (파라미터는 parameters 딕셔너리로 분리되어 넘어감)
            raw_url = str(link.get('url', ''))
            clean_url = self._strip_query_string(raw_url)

            normalized_params = self._normalize_parameters(link.get('params', {}))
            inferred_params = False
            if not normalized_params:
                normalized_params = merge_inferred_query_params(clean_url, normalized_params)
                inferred_params = bool(normalized_params)
            # ✨ 타입 충돌 방지용 새 딕셔너리
            parameters: dict[str, Any] = dict(normalized_params)
            inferred_keys: set[str] = set(normalized_params.keys()) if inferred_params else set()
            if page_data.dynamic_tokens:
                parameters.update(page_data.dynamic_tokens)
            confidence = self._build_parameter_confidence(
                parameters,
                default_level="high",
                inferred_keys=inferred_keys,
            )
            if page_data.dynamic_tokens:
                for token_name in page_data.dynamic_tokens.keys():
                    token_key = str(token_name).strip()
                    if token_key:
                        confidence[token_key] = "medium"

            link_desc = "Link Query Params"
            if inferred_params:
                link_desc += " inferred:true"
            surfaces.append(AttackSurface(
                url=clean_url,
                method=method,
                param_location=ParamLocation.QUERY,
                parameters=parameters,
                headers=page_data.headers,
                cookies=page_data.cookies,
                dynamic_tokens=page_data.dynamic_tokens.copy(),
                server_info=page_data.server_info.copy(),
                source_url=str(page_data.url),
                description=link_desc,
                parameter_confidence=confidence,
            ))

        # ==========================================
        # 3. Path 파라미터 기반 AttackSurface 추출
        # ==========================================
        candidate_urls: list[tuple[str, str]] = []
        for form in forms:
            action = str(form.get("action") or "")
            if action:
                method_hint = str(
                    form.get("data_orig_method") or form.get("method", "GET")
                ).upper()
                candidate_urls.append((action, method_hint))
        for link in links:
            link_url = str(link.get("url") or "")
            if link_url:
                candidate_urls.append((link_url, str(link.get("method", "GET")).upper()))

        seen_path_sigs: set[str] = set()
        for raw_url, method_hint in candidate_urls:
            extracted = path_params.extract_path_surface(raw_url)
            if not extracted:
                continue
            template_url, path_parameters, _ = extracted
            try:
                http_method = HttpMethod(method_hint)
            except ValueError:
                http_method = HttpMethod.GET

            path_params_only = dict(path_parameters)
            sig = f"path:{template_url}:{http_method.value}:{sorted(path_params_only.keys())}"
            if sig in seen_path_sigs:
                continue
            seen_path_sigs.add(sig)

            surfaces.append(AttackSurface(
                url=template_url,
                method=http_method,
                param_location=ParamLocation.PATH,
                parameters=path_params_only,
                headers=page_data.headers,
                cookies=page_data.cookies,
                dynamic_tokens=page_data.dynamic_tokens.copy(),
                server_info=page_data.server_info.copy(),
                source_url=str(page_data.url),
                description="Path Parameter",
                parameter_confidence=self._build_parameter_confidence(path_params_only, default_level="high"),
            ))
            self._path_surfaces_found += 1

        return self._dedupe_surfaces(surfaces)

    async def process_page(self, page_data: PageData) -> None:
        """
        PageData를 분석하여 AttackSurface를 추출하고 퍼저로 직배송
        ✨ [핵심 수정] run_in_executor를 통한 비동기 논블로킹(Non-blocking) 호출 적용
        """
        loop = asyncio.get_running_loop()

        # CPU 연산이 많은 DOM 순회 및 파싱 로직을 스레드 풀로 넘겨 크롤러 통신 지연 방지
        surfaces = await loop.run_in_executor(
            None, self._extract_surfaces_sync, page_data
        )

        # ==========================================
        # 4.. 중복 검증 및 퍼저 콜백 호출 (이벤트 루프에서 가볍게 처리)
        # ==========================================
        for surface in surfaces:
            if not surface.url: continue
            if is_low_value_fuzz_url(str(surface.url)):
                self._low_value_surfaces_skipped += 1
                continue
            if self.skip_auth_surfaces and is_auth_fuzz_surface(
                str(surface.url),
                surface.parameters,
                login_urls=self._login_urls,
                extra_path_markers=self._exclude_auth_paths,
            ):
                self._auth_surfaces_skipped += 1
                continue
            # DVWA CSRF page changes current user password; exclude from active testing.
            if "/vulnerabilities/csrf/" in str(surface.url).lower():
                continue
            # 동적 토큰(CSRF 등) 보호 surface 처리:
            # - 기본(skip_csrf_surfaces=True): CSRF 폼은 퍼징 제외.
            # - --fuzz-csrf 옵션 시 request_builder가 매 요청마다 토큰 갱신 후 공격.
            if self.skip_csrf_surfaces and getattr(surface, "dynamic_tokens", None):
                self._skipped_csrf_count += 1
                continue

            sig = self._generate_signature(surface)
            if sig in self._seen_signatures: continue

            self._seen_signatures.add(sig)

            logger.debug(f"[SurfaceBuilder] 퍼저로 전송: {surface.url}")

            try:
                result = self.fuzzer_callback(surface)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                logger.exception(
                    "[SurfaceBuilder] Fuzzer callback failed (url=%s): %s",
                    surface.url,
                    exc,
                )

    def get_stats(self) -> dict:
        return {
            "unique_surfaces_sent": len(self._seen_signatures),
            "csrf_surfaces_skipped": self._skipped_csrf_count,
            "path_surfaces_found": self._path_surfaces_found,
            "low_value_surfaces_skipped": self._low_value_surfaces_skipped,
            "auth_surfaces_skipped": self._auth_surfaces_skipped,
        }