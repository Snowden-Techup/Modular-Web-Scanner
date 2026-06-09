from __future__ import annotations

import asyncio
import json
import traceback
from urllib.parse import urlparse

from core import AttackSurface
from core.queue_manager import QueueManager
from crawler.engine import CrawlConfig, CrawlerEngine
from crawler.session_manager import AuthConfig
from modules.bruteforce.target_prep import (
    apply_username_to_surfaces,
    build_targeted_bruteforce_surface,
)
from parsers.surface_builder import SurfaceBuilder
from crawler.url_filter import URLFilter


def _export_surfaces_json(surfaces: list[AttackSurface], output_path: str) -> None:
    payload = [surface.to_dict() for surface in surfaces]
    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)


def export_surfaces_if_configured(args, surfaces: list[AttackSurface]) -> bool:
    """Write surfaces to --surfaces-output when configured. Returns True on success."""
    output_path = (getattr(args, "surfaces_output", "") or "").strip()
    if not output_path:
        return False
    if not surfaces:
        return False
    try:
        _export_surfaces_json(surfaces, output_path)
        print(f"[*] Attack surfaces exported: {output_path}")
        return True
    except OSError as exc:
        print(f"Failed to export attack surfaces JSON: {exc}")
        return False


def _parse_local_storage(args) -> dict:
    local_storage_data = getattr(args, "local_storage", {})
    if isinstance(local_storage_data, str):
        try:
            return json.loads(local_storage_data)
        except Exception:
            return {}
    return dict(local_storage_data or {})


def _auth_config_from_args(args) -> AuthConfig | None:
    login_url = (getattr(args, "login_url", "") or "").strip()
    username = (getattr(args, "username", "") or "").strip()
    password = (getattr(args, "password", "") or "").strip()
    if not (login_url and username and password):
        return None
    return AuthConfig(
        login_url=login_url,
        username=username,
        password=password,
        username_field=args.username_field,
        password_field=args.password_field,
        csrf_token_name=args.csrf_field or None,
        submit_field=args.submit_field or None,
        login_body_format=getattr(args, "login_body_format", "auto"),
    )


def _setup_url_filter(args, start_url: str) -> URLFilter:
    url_filter = URLFilter()
    url_filter.add_allowed_domain(urlparse(start_url).netloc)
    exclude_patterns = getattr(args, "exclude_urls", []) or []
    if exclude_patterns:
        url_filter = URLFilter(excluded_patterns=exclude_patterns)
        url_filter.add_allowed_domain(urlparse(start_url).netloc)
    return url_filter


async def resolve_surfaces(args, base_url: str, cookies: dict[str, str]) -> list[AttackSurface]:
    if args.type == "bruteforce":
        return await _resolve_bruteforce_surfaces(args, base_url, cookies)

    surfaces = await _resolve_crawled_surfaces(
        args=args,
        start_url=base_url,
        cookies=cookies,
    )

    if not surfaces:
        print("Crawler returned no attack surfaces. Exiting.")
    return surfaces


async def _resolve_crawled_surfaces(
        args,
        start_url: str,
        cookies: dict[str, str] | None = None,
) -> list[AttackSurface]:
    """
    크롤러(정적/동적) → 큐 → SurfaceBuilder 파이프라인.
    """
    crawl_mode = getattr(args, "crawl_mode", "static")
    if crawl_mode not in ("static", "dynamic"):
        print(f"Invalid crawl mode: {crawl_mode!r}. Use static or dynamic.")
        return []

    queue_manager = QueueManager()
    surfaces: list[AttackSurface] = []

    async def _collect(surface: AttackSurface) -> None:
        surfaces.append(surface)

    attack_type = (getattr(args, "type", "") or "").strip()
    fuzz_auth = bool(getattr(args, "fuzz_auth", False))
    skip_auth_surfaces = not fuzz_auth and attack_type != "bruteforce"
    login_url = (getattr(args, "login_url", "") or "").strip()
    login_urls = (login_url,) if login_url else ()
    exclude_auth_paths = tuple(
        p.strip()
        for p in (getattr(args, "exclude_auth_paths", None) or [])
        if (p or "").strip()
    )

    surface_builder = SurfaceBuilder(
        fuzzer_callback=_collect,
        skip_csrf_surfaces=not bool(getattr(args, "fuzz_csrf", False)),
        skip_auth_surfaces=skip_auth_surfaces,
        login_urls=login_urls,
        exclude_auth_paths=exclude_auth_paths,
    )
    url_filter = _setup_url_filter(args, start_url)

    crawler = CrawlerEngine(
        queue_manager=queue_manager,
        config=CrawlConfig(),
    )
    crawler.url_filter = url_filter
    crawler.session_manager.url_filter = url_filter

    if cookies:
        crawler.session_manager.set_cookies(cookies)

    run_static = crawl_mode == "static"
    run_dynamic = crawl_mode == "dynamic"

    try:
        # 정적 크롤 또는 하이브리드: aiohttp 폼 로그인 (전통 앱·세션 쿠키)
        if run_static:
            login_ready = await _login_if_configured(args, crawler)
            if not login_ready:
                return []
        elif _auth_config_from_args(args) is None:
            login_ready = True
        else:
            # dynamic 전용 + 로그인 설정: Playwright가 브라우저 로그인 담당
            login_ready = True
            print("[*] Dynamic crawl: browser login will run in Playwright (aiohttp login skipped).")

        updated_cookies = crawler.session_manager.get_cookies()
        auth_config = _auth_config_from_args(args)

        spa_crawler = None
        if run_dynamic:
            from crawler.spa.engine import SPACrawlerEngine

            spa_crawler = SPACrawlerEngine(
                queue_manager=queue_manager,
                target_url=start_url,
                cookies=updated_cookies,
                local_storage=_parse_local_storage(args),
                url_filter=url_filter,
                auth_config=auth_config,
                max_routes=int(getattr(args, "spa_max_routes", 50)),
                safe_click=not bool(getattr(args, "unsafe_click", False)),
            )

        mode_label = {"static": "static", "dynamic": "dynamic (SPA)"}
        print(f"[*] Crawl mode: {mode_label[crawl_mode]}")

        async def _run_spa_crawler() -> None:
            assert spa_crawler is not None
            async with spa_crawler:
                await spa_crawler.start()

        async def run_producers():
            tasks: list[asyncio.Task] = []
            if run_static:
                tasks.append(asyncio.create_task(crawler.start(start_url)))
            if run_dynamic and spa_crawler is not None:
                tasks.append(asyncio.create_task(_run_spa_crawler()))
            try:
                if tasks:
                    await asyncio.gather(*tasks)
            finally:
                await queue_manager.add_page(None)

        await asyncio.gather(
            surface_builder.consume_from_queue(queue_manager),
            run_producers(),
        )
        sb_stats = surface_builder.get_stats()
        skipped_csrf = int(sb_stats.get("csrf_surfaces_skipped", 0) or 0)
        if skipped_csrf:
            print(
                f"[*] CSRF-protected surfaces skipped: {skipped_csrf} "
                f"(use --fuzz-csrf to include them in fuzzing)"
            )
        skipped_auth = int(sb_stats.get("auth_surfaces_skipped", 0) or 0)
        if skipped_auth:
            print(
                f"[*] Auth/login surfaces skipped: {skipped_auth} "
                f"(use --fuzz-auth or bruteforce mode to include them)"
            )
    except Exception as exc:
        print(f"Failed to crawl target URL {start_url}: {exc}")
        traceback.print_exc()
        return []
    finally:
        try:
            await crawler.session_manager.close()
        except Exception:
            pass

    print(f"[*] Crawler mode ({crawl_mode}): discovered {len(surfaces)} attack surface(s).")
    export_surfaces_if_configured(args, surfaces)
    return surfaces


async def _login_and_get_cookies(args, *, extra_cookies: dict[str, str]) -> dict[str, str]:
    """
    --login-url 이 설정된 경우 임시 크롤러 세션으로 로그인한 뒤 쿠키를 반환한다.
    """
    login_url = (args.login_url or "").strip()
    if not login_url:
        return dict(extra_cookies)

    crawler = CrawlerEngine(queue_manager=None, config=CrawlConfig())
    if extra_cookies:
        crawler.session_manager.set_cookies(extra_cookies)
    try:
        await crawler.session_manager.create_session()
        success = await _login_if_configured(args, crawler)
        if success:
            session_cookies = crawler.session_manager.get_cookies()
            merged = dict(extra_cookies)
            merged.update(session_cookies)
            return merged
    finally:
        try:
            await crawler.session_manager.close()
        except Exception:
            pass
    return dict(extra_cookies)


async def _login_if_configured(args, crawler: CrawlerEngine) -> bool:
    username = (args.username or "").strip()
    password = (args.password or "").strip()
    login_url = (args.login_url or "").strip()

    if not username and not password and not login_url:
        return True

    if not (username and password and login_url):
        print("Login requires --login-url, --username, and --password together.")
        return False

    auth_config = AuthConfig(
        login_url=login_url,
        username=username,
        password=password,
        username_field=args.username_field,
        password_field=args.password_field,
        csrf_token_name=args.csrf_field or None,
        submit_field=args.submit_field or None,
        login_body_format=getattr(args, "login_body_format", "auto"),
    )

    if not await crawler.session_manager.login(auth_config):
        print(f"Login failed: {login_url}")
        return False

    print(f"[*] Login succeeded: {login_url}")
    return True


async def _resolve_bruteforce_surfaces(
        args,
        base_url: str,
        cookies: dict[str, str],
) -> list[AttackSurface]:
    if (getattr(args, "bf_target_url", "") or "").strip():
        session_cookies = await _login_and_get_cookies(args, extra_cookies=cookies)
        target_label = args.bf_target_param or args.bf_fuzz_param
        print(f"[*] Targeted URL mode: {args.bf_target_url} [{target_label}=FUZZ]")
        targeted = [build_targeted_bruteforce_surface(args, session_cookies)]
        return apply_username_to_surfaces(
            targeted,
            username_param=args.bf_username_param,
            username_value=args.bf_username,
        )

    surfaces = await _resolve_crawled_surfaces(
        args=args,
        start_url=base_url,
        cookies=cookies,
    )
    surfaces = apply_username_to_surfaces(
        surfaces,
        username_param=args.bf_username_param,
        username_value=args.bf_username,
    )
    if not surfaces:
        print(
            "No attack surfaces collected for bruteforce mode. "
            "Use --bf-target-url for direct targeting."
        )
        return []
    print(f"[*] Crawler mode: passing {len(surfaces)} surface(s) to bruteforce module heuristics.")
    return surfaces
