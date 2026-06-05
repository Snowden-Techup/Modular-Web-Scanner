"""SPA 동적 크롤러 오케스트레이터 (통합 제어 엔진)"""

from __future__ import annotations

import logging
import os
import tempfile
from datetime import datetime
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

from playwright.async_api import async_playwright

from core.models import PageData
from crawler.spa.browser import (
    build_auth_headers,
    build_playwright_cookies,
    cookies_as_dict,
    interact_and_submit,
    playwright_auth_login,
    sync_cookies_from_context,
    sync_storage_from_browser,
    wait_for_page_settle,
)
from crawler.spa.capture import (
    build_synthesized_html,
    collect_routes_from_page,
    collect_global_response_metadata,
    enqueue_routes,
    extract_graphql_schema,
    intercept_request,
    intercept_response,
    probe_endpoint_methods_precise,
    record_api_candidate,
    should_collect_url,
)
from crawler.spa.js_analyzer import seed_api_candidates_from_scripts

if TYPE_CHECKING:
    from crawler.session_manager import AuthConfig
    from crawler.url_filter import URLFilter

logger = logging.getLogger(__name__)

DEFAULT_HASH_ROUTE_SEED_FRAGMENTS = (
    "/login",
    "/register",
    "/contact",
    "/about",
    "/search",
    "/profile",
    "/account",
    "/user",
    "/cart",
    "/basket",
    "/orders",
    "/checkout",
    "/admin",
    "/admin/logs",
    "/board",
    "/board/write",
    "/books",
    "/reviews",
    "/forgot-password",
    "/reset-password",
)


class SPACrawlerEngine:
    """Playwright 기반 SPA 동적 크롤러."""

    def __init__(
        self,
        queue_manager,
        target_url: str,
        cookies=None,
        local_storage=None,
        timeout: int = 15000,
        route_timeout: int | None = None,
        *,
        url_filter: "URLFilter | None" = None,
        auth_config: "AuthConfig | None" = None,
        max_routes: int = 50,
        safe_click: bool = True,
        hash_route_seed_fragments: list[str] | None = None,
    ):
        self.queue_manager = queue_manager
        self.target_url = target_url
        self.cookies = cookies or {}
        self.local_storage = dict(local_storage or {})
        self.timeout = timeout
        self.route_timeout = (
            route_timeout if route_timeout is not None else max(3000, timeout // 2)
        )
        self.url_filter = url_filter
        self.auth_config = auth_config
        self.max_spa_routes = max_routes
        self.safe_click = safe_click
        self.hash_route_seed_fragments = (
            list(DEFAULT_HASH_ROUTE_SEED_FRAGMENTS)
            if hash_route_seed_fragments is None
            else [str(fragment).strip() for fragment in hash_route_seed_fragments if str(fragment).strip()]
        )
        self.target_domain = urlparse(self.target_url).hostname
        self._login_verified = False
        self._reset_state()

        fd, self.dummy_file_path = tempfile.mkstemp(prefix="mws_dummy_", suffix=".png")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(
                    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
                    b"\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
                    b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01"
                    b"\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
                )
        except Exception:
            try:
                os.close(fd)
            except Exception:
                pass

    def _reset_state(self) -> None:
        self._crawl_started_at: datetime | None = None
        self._crawl_ended_at: datetime | None = None
        self._url_cache: dict[str, str] = {}
        self.found_urls: set[str] = set()
        self.api_endpoints: dict = {}
        self.default_server_name: str = ""
        self.route_depths: dict[str, int] = {}
        self.current_route_url: str = self.target_url
        self.current_route_depth: int = 0
        self.id_sample_slots: dict[str, dict[str, int]] = {}
        self.graphql_endpoint_paths: set[str] = set()
        self.graphql_captures: dict[str, list[dict[str, str]]] = {}
        self.observed_query_params: dict[str, set[str]] = {}
        self.observed_query_samples: dict[str, dict[str, str]] = {}
        self.observed_body_params: dict[str, set[str]] = {}
        self.observed_body_samples: dict[str, dict[str, str]] = {}
        self.observed_body_content_types: dict[str, str] = {}
        self.metrics = {
            "apis_found": 0,
            "links_extracted": 0,
            "oos_blocked": 0,
            "payload_dropped": 0,
            "graphql_schemas": 0,
            "apis_clustered": 0,
            "id_samples_preserved": 0,
            "js_scripts_scanned": 0,
            "js_endpoints_seeded": 0,
        }

    def _summary_dict(self) -> dict[str, str | int]:
        duration = 0.0
        if self._crawl_started_at and self._crawl_ended_at:
            duration = (self._crawl_ended_at - self._crawl_started_at).total_seconds()
        return {
            "apis_found": int(self.metrics.get("apis_found", 0) or 0),
            "links_extracted": int(self.metrics.get("links_extracted", 0) or 0),
            "graphql_schemas": int(self.metrics.get("graphql_schemas", 0) or 0),
            "payload_dropped": int(self.metrics.get("payload_dropped", 0) or 0),
            "routes_visited": int(len(self.route_depths)),
            "duration": f"{duration:.2f}s",
        }

    def _log_summary(self) -> None:
        summary = self._summary_dict()
        logger.info("========== SPA 크롤링 종료 ==========")
        logger.info(
            "[SPA] API 발견: %s, 링크 발견: %s, GraphQL 스키마: %s, 드롭: %s, 방문 라우트: %s, 소요 시간: %s",
            summary["apis_found"],
            summary["links_extracted"],
            summary["graphql_schemas"],
            summary["payload_dropped"],
            summary["routes_visited"],
            summary["duration"],
        )

    def get_summary(self) -> dict[str, str | int]:
        return self._summary_dict()

    def _cleanup_dummy_file(self) -> None:
        path = getattr(self, "dummy_file_path", None)
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass

    def record_seeded_api(
            self,
            *,
            method: str,
            url: str,
            post_data: str | None = None,
            req_content_type: str = "",
            status: int | None = None,
            content_type: str | None = None,
            source: str = "seed",
    ) -> tuple[str | None, bool]:
        return record_api_candidate(
            self,
            method=method,
            url=url,
            post_data=post_data,
            req_content_type=req_content_type,
            status=status,
            content_type=content_type,
            route_context="",
            source=source,
        )

    def _build_hash_seed_routes(self) -> list[str]:
        if not self.hash_route_seed_fragments:
            return []
        parsed = urlparse(self.target_url)
        base_path = parsed.path or "/"
        seeded_routes: list[str] = []
        seen: set[str] = set()
        for raw_fragment in self.hash_route_seed_fragments:
            fragment = str(raw_fragment).strip()
            if not fragment:
                continue
            if fragment.startswith("#"):
                fragment = fragment[1:]
            if not (fragment.startswith("/") or fragment.startswith("!/")):
                fragment = f"/{fragment}"
            route = urlunparse((parsed.scheme, parsed.netloc, base_path, "", "", fragment))
            if route in seen or route == self.target_url:
                continue
            seen.add(route)
            seeded_routes.append(route)
        return seeded_routes

    async def __aenter__(self) -> "SPACrawlerEngine":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        self._cleanup_dummy_file()

    def _intercept_request(self, request) -> None:
        intercept_request(self, request)

    def _intercept_response(self, response) -> None:
        intercept_response(self, response)

    async def start(self) -> None:
        self._reset_state()
        self._crawl_started_at = datetime.now()
        final_html = ""
        graphql_html = ""

        login_url = (
            self.auth_config.login_url.strip()
            if self.auth_config and self.auth_config.login_url
            else None
        )

        async with async_playwright() as p:
            browser = None
            context = None
            try:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                    ),
                )

                if self.local_storage:
                    await context.add_init_script(
                        """(items) => {
                            for (const [k, v] of Object.entries(items || {})) {
                                if (k != null && v != null) localStorage.setItem(String(k), String(v));
                            }
                        }""",
                        dict(self.local_storage),
                    )

                playwright_cookies = build_playwright_cookies(
                    target_url=self.target_url,
                    cookies=self.cookies,
                    login_url=login_url,
                )
                if playwright_cookies:
                    await context.add_cookies(playwright_cookies)

                page = await context.new_page()

                async def handle_dialog(dialog):
                    try:
                        await dialog.dismiss()
                        logger.debug(
                            "[SPA Crawler] Dismissed %s dialog on %s",
                            dialog.type,
                            page.url,
                        )
                    except Exception as exc:
                        logger.debug("[SPA Crawler] Dialog dismiss failed: %s", exc)

                page.on("dialog", handle_dialog)

                async def route_interceptor(route):
                    if route.request.resource_type in ("image", "font", "media"):
                        await route.abort()
                    else:
                        await route.continue_()

                await page.route("**/*", route_interceptor)
                page.on("request", self._intercept_request)
                page.on("response", self._intercept_response)

                if self.auth_config:
                    login_ok = await playwright_auth_login(self, page, context)
                    if not login_ok:
                        logger.warning(
                            "[SPA Crawler] Auth login could not be verified; "
                            "crawl continues but API calls may return 401."
                        )

                try:
                    await page.goto(
                        self.target_url,
                        wait_until="domcontentloaded",
                        timeout=self.timeout,
                    )
                    self.current_route_url = self.target_url
                    self.current_route_depth = 0
                    self.route_depths[self.target_url] = 0
                    await wait_for_page_settle(page, context_label="base route load")
                    final_html = await page.content()
                except Exception as e:
                    logger.debug("[SPA Crawler] Load timeout on base url: %s", e)

                try:
                    await seed_api_candidates_from_scripts(self, page, context)
                except Exception as exc:
                    logger.debug("[SPA Crawler] JS endpoint seeding failed: %s", exc)

                await interact_and_submit(self, page)
                await interact_and_submit(self, page)
                await sync_storage_from_browser(self, page)

                routes_to_visit: list[str] = []
                queued_routes: set[str] = set()
                visited_routes = {self.target_url}

                initial_routes = self._build_hash_seed_routes() + await collect_routes_from_page(page)
                enqueue_routes(
                    self,
                    initial_routes,
                    routes_to_visit,
                    queued_routes,
                    visited_routes,
                    route_depths=self.route_depths,
                    parent_depth=0,
                )

                visit_count = 0
                max_spa_routes = self.max_spa_routes

                while routes_to_visit and visit_count < max_spa_routes:
                    route = routes_to_visit.pop(0)
                    if route in visited_routes:
                        continue
                    if not should_collect_url(self, route):
                        continue
                    if self.url_filter is not None and self.url_filter.is_visited(route):
                        visited_routes.add(route)
                        continue

                    visited_routes.add(route)
                    if self.url_filter is not None:
                        self.url_filter.mark_visited(route)
                    visit_count += 1
                    depth = int(self.route_depths.get(route, 1))
                    self.current_route_url = route
                    self.current_route_depth = depth

                    try:
                        progress_pct = (visit_count / max_spa_routes) * 100
                        print(
                            f"\rProgress: {progress_pct:6.2f}% ({visit_count}/{max_spa_routes})"
                            + " " * 20,
                            end="",
                            flush=True,
                        )
                        await page.goto(
                            route,
                            wait_until="domcontentloaded",
                            timeout=self.route_timeout,
                        )
                        await wait_for_page_settle(page, context_label=f"route load:{route}")
                        await interact_and_submit(self, page)
                        await interact_and_submit(self, page)
                        await sync_storage_from_browser(self, page)
                        new_routes = await collect_routes_from_page(page)
                        enqueue_routes(
                            self,
                            new_routes,
                            routes_to_visit,
                            queued_routes,
                            visited_routes,
                            route_depths=self.route_depths,
                            parent_depth=depth,
                        )
                    except Exception as exc:
                        logger.debug("[SPA Crawler] Route visit failed on %s: %s", route, exc)
                        continue
                if visit_count >= max_spa_routes:
                    completion_msg = f"100.00% ({visit_count}/{max_spa_routes} routes, limit reached)"
                else:
                    completion_msg = f"100.00% ({visit_count} routes processed, queue exhausted)"
                print(f"\rProgress: {completion_msg}" + " " * 20, flush=True)

                await sync_cookies_from_context(self, context)
                await probe_endpoint_methods_precise(self, context)

            except Exception as e:
                logger.error(
                    "[SPA Crawler] Critical Engine Failure on %s: %s",
                    self.target_url,
                    e,
                )
            finally:
                if context:
                    try:
                        await context.close()
                    except Exception:
                        pass
                if browser:
                    try:
                        await browser.close()
                    except Exception:
                        pass
                self._cleanup_dummy_file()

        if not final_html.strip():
            final_html = "<html><body></body></html>"

        page_headers, page_server_info = collect_global_response_metadata(self)
        if page_server_info:
            self.default_server_name = str(page_server_info.get("web_server") or "")
        final_html = build_synthesized_html(self, final_html, graphql_html)
        logger.info(
            "[SPA Crawler] APIs: %s (Clustered: %s, ID Samples: %s), Links: %s, GraphQL: %s, Dropped: %s, JS Scripts: %s, JS Seeds: %s",
            self.metrics["apis_found"],
            self.metrics["apis_clustered"],
            self.metrics["id_samples_preserved"],
            self.metrics["links_extracted"],
            self.metrics["graphql_schemas"],
            self.metrics["payload_dropped"],
            self.metrics["js_scripts_scanned"],
            self.metrics["js_endpoints_seeded"],
        )

        page_data = PageData(
            url=self.target_url,
            html=final_html,
            depth=0,
            cookies=cookies_as_dict(self.cookies),
            headers={**page_headers, **build_auth_headers(self.local_storage)},
            dynamic_tokens={},
            server_info=page_server_info,
        )
        await self.queue_manager.add_page(page_data)
        self._crawl_ended_at = datetime.now()
        self._log_summary()
