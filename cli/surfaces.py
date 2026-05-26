from __future__ import annotations

import asyncio
import json

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
        return []
    return surfaces


async def _resolve_crawled_surfaces(
    args,
    start_url: str,
    cookies: dict[str, str] | None = None,
) -> list[AttackSurface]:
    """
    크롤러(CrawlerEngine) → 큐(QueueManager) → 파서(SurfaceBuilder) 파이프라인을 실행하고
    파서가 만들어낸 AttackSurface 목록을 반환한다.
    """
    queue_manager = QueueManager()
    surfaces: list[AttackSurface] = []

    async def _collect(surface: AttackSurface) -> None:
        surfaces.append(surface)

    surface_builder = SurfaceBuilder(fuzzer_callback=_collect)
    crawler = CrawlerEngine(
        queue_manager=queue_manager,
        config=CrawlConfig(),
    )
    # CLI 인자로 받은 제외 패턴을 URLFilter에 주입
    exclude_patterns = getattr(args, "exclude_urls", [])
    if exclude_patterns:
        custom_filter = URLFilter(excluded_patterns=exclude_patterns)
        crawler.url_filter = custom_filter
        crawler.session_manager.url_filter = custom_filter

    # CLI에서 전달받은 쿠키(-c 옵션)를 크롤러 세션에 주입
    if cookies:
        crawler.session_manager.set_cookies(cookies)

    try:
        login_ready = await _login_if_configured(args, crawler)
        if not login_ready:
            return []

        # 크롤러(생산자)와 파서(소비자)를 동시에 실행
        # crawler.start()가 종료 신호(sentinel=None)를 큐에 넣으면
        # surface_builder.consume_from_queue()가 루프를 빠져나와 완료
        await asyncio.gather(
            surface_builder.consume_from_queue(queue_manager),
            crawler.start(start_url),
        )
    except Exception as exc:
        print(f"Failed to crawl target URL {start_url}: {exc}")
        return []
    finally:
        # login 단계에서 조기 종료되면 crawler.start() context manager가
        # 실행되지 않아 세션이 남을 수 있으므로 여기서 항상 정리한다.
        try:
            await crawler.session_manager.close()
        except Exception:
            pass

    print(f"[*] Crawler mode: discovered {len(surfaces)} attack surface(s).")
    surfaces_output = (getattr(args, "surfaces_output", "") or "").strip()
    if surfaces_output:
        try:
            _export_surfaces_json(surfaces, surfaces_output)
            print(f"[*] Attack surfaces exported: {surfaces_output}")
        except OSError as exc:
            print(f"Failed to export attack surfaces JSON: {exc}")
    return surfaces


async def _login_and_get_cookies(args, *, extra_cookies: dict[str, str]) -> dict[str, str]:
    """
    --login-url 이 설정된 경우 임시 크롤러 세션으로 로그인한 뒤 쿠키를 반환한다.
    로그인 설정이 없거나 실패하면 extra_cookies 를 그대로 반환한다.
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
