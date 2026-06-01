"""CLI entrypoint: parse arguments, run fuzzer, export reports."""

from __future__ import annotations

import asyncio
import sys
import warnings

from cli.options import parse_bf_length, parse_cookies
from cli.parser import parse_arguments
from cli.runner import run_scan
from cli.surfaces import resolve_surfaces
from fuzzer.request_builder import set_graphql_safe_mode


async def main() -> None:
    args = parse_arguments()
    if getattr(args, "login_json", False):
        args.login_body_format = "json"
    if args.level is not None:
        args.sqli_evasion_level = args.level
        args.osci_evasion_level = args.level
        args.lfi_evasion_level = args.level
        args.ssrf_evasion_level = min(args.level, 2)
    # GraphQL Safe Mode 토글 (기본은 안전, --graphql-unsafe 시 Mutation 공격 허용)
    if getattr(args, "graphql_unsafe", False):
        print(
            "[WARNING] GraphQL unsafe mode enabled: mutations will be attacked; "
            "server/database state may change."
        )
        set_graphql_safe_mode(False)
    else:
        set_graphql_safe_mode(True)
    if getattr(args, "unsafe_click", False):
        print(
            "[WARNING] SPA unsafe click enabled: non-submit UI buttons may be clicked "
            "(higher coverage; logout/session loss risk)."
        )
    if getattr(args, "fuzz_csrf", False):
        print(
            "[WARNING] CSRF fuzzing enabled: dynamic-token surfaces will be attacked "
            "(slower; may invalidate sessions or trigger side effects)."
        )
    if getattr(args, "fuzz_auth", False):
        print(
            "[WARNING] Auth endpoint fuzzing enabled: login/token surfaces will be attacked "
            "(may invalidate sessions or trigger account lockout)."
        )
    try:
        args.bf_min_length, args.bf_max_length = parse_bf_length(
            args.bf_length,
            args.bf_max_length,
        )
    except ValueError as exc:
        print(str(exc))
        return

    cookies = parse_cookies(args.cookie) if args.cookie else {}
    base_url = args.url.rstrip("/")
    surfaces = await resolve_surfaces(args, base_url, cookies)
    if not surfaces:
        return

    await run_scan(args, base_url=base_url, surfaces=surfaces)


if __name__ == "__main__":
    if sys.platform == "win32":
        # Suppress asyncio Windows loop policy deprecation noise on Python 3.13+.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
