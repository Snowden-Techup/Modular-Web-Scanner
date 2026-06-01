from __future__ import annotations

import argparse
import os


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Modular Web Scanner (MWS) - integrated web vulnerability scanner CLI"
    )
    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="DVWA base URL (e.g. http://127.0.0.1/DVWA)",
    )
    parser.add_argument(
        "-r",
        "--rps",
        type=int,
        default=100,
        help="Target requests per second throttle (default: 100)",
    )
    parser.add_argument(
        "-c",
        "--cookie",
        type=str,
        default="",
        help="Cookie header value (e.g. 'PHPSESSID=abc; security=low')",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=0,
        help="Number of queue workers (0 = auto-calculate based on rps)",
    )
    parser.add_argument(
        "--login-url",
        type=str,
        default="",
        help="Login page URL used before crawling (e.g. http://target/login.php)",
    )
    parser.add_argument(
        "--username",
        type=str,
        default="",
        help="Login username used before crawling",
    )
    parser.add_argument(
        "--password",
        type=str,
        default="",
        help="Login password used before crawling",
    )
    parser.add_argument(
        "--username-field",
        type=str,
        default="username",
        help="Form field name for username (default: username)",
    )
    parser.add_argument(
        "--password-field",
        type=str,
        default="password",
        help="Form field name for password (default: password)",
    )
    parser.add_argument(
        "--csrf-field",
        type=str,
        default="user_token",
        help="CSRF token field name on login form (default: user_token)",
    )
    parser.add_argument(
        "--submit-field",
        type=str,
        default="Login",
        help="Submit field name on login form (default: Login)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="scan_report.json",
        help="JSON report output path",
    )
    parser.add_argument(
        "--login-body-format",
        type=str,
        choices=["auto", "form", "json"],
        default="auto",
        help="Login POST body format: form (x-www-form-urlencoded), json, or auto-detect (default: auto)",
    )
    parser.add_argument(
        "--login-json",
        action="store_true",
        help="Shorthand for --login-body-format json (JSON {\"username\":...} API login)",
    )
    parser.add_argument(
        "--surfaces-output",
        type=str,
        default="attack_surfaces.json",
        help="JSON output path for crawled attack surfaces",
    )
    parser.add_argument(
        "-t",
        "--type",
        type=str,
        default="all",
        choices=["sqli", "osci", "bruteforce", "lfi", "file_upload", "ssrf", "stored_xss", "reflected_xss", "oob", "all"],
        help=(
            "Attack category (default: all). For bruteforce without --bf-target-url, "
            "surfaces come from the crawler; BruteforceModule.get_target_parameters filters targets."
        ),
    )
    parser.add_argument(
        "--level",
        type=int,
        choices=[0, 1, 2, 3],
        default=None,
        metavar="N",
        help=(
            "Set SQLi, OSCi, LFI, and SSRF evasion level to N at once (bruteforce unchanged). "
            "SSRF is capped at 2. Overrides --sqli-evasion-level, --osci-evasion-level, --lfi-evasion-level, "
            "and --ssrf-evasion-level when set."
        ),
    )
    parser.add_argument(
        "--bf-wordlist",
        type=str,
        default=os.path.join("config", "payloads", "bruteforce", "common_passwords.txt"),
        help="Bruteforce dictionary file path (absolute or relative)",
    )
    parser.add_argument(
        "--bf-disable-mutation",
        action="store_true",
        help="Disable password mutation in bruteforce dictionary mode",
    )
    parser.add_argument(
        "--bf-mutation-level",
        type=int,
        choices=[0, 1, 2, 3],
        default=1,
        help=(
            "Mutation intensity for bruteforce dictionary mode "
            "(0=none, 1=basic, 2=extended suffixes, 3=extended+leet)"
        ),
    )
    parser.add_argument(
        "--bf-true-random",
        action="store_true",
        help="Enable exclusive true-random bruteforce mode (dictionary disabled)",
    )
    parser.add_argument(
        "--bf-charset",
        type=str,
        default="abcdefghijklmnopqrstuvwxyz0123456789",
        help="Charset for true random bruteforce mode",
    )
    parser.add_argument(
        "--bf-max-length",
        type=int,
        default=3,
        help="Maximum length for true random bruteforce mode",
    )
    parser.add_argument(
        "--bf-min-length",
        type=int,
        default=1,
        help="Minimum length for true random bruteforce mode",
    )
    parser.add_argument(
        "--bf-length",
        type=str,
        default="",
        help=(
            "True-random brute-force length or range. "
            "Examples: --bf-length 8 (means 1~8), --bf-length 2~8. "
            "Overrides --bf-max-length."
        ),
    )
    parser.add_argument(
        "--bf-max-dictionary",
        type=int,
        default=0,
        help="Cap dictionary payload count (0=all)",
    )
    parser.add_argument(
        "--bf-max-true-random",
        type=int,
        default=0,
        help="Cap true random payload count (0=all)",
    )
    parser.add_argument(
        "--bf-stop-on-first-hit",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Stop bruteforce module after first verified credential hit (default: enabled)",
    )
    parser.add_argument(
        "--bf-target-url",
        type=str,
        default="",
        metavar="URL",
        help=(
            "Bruteforce: single explicit URL (requires --bf-fuzz-param / --bf-method as needed). "
            "If omitted, crawl -u and filter with module heuristics."
        ),
    )
    parser.add_argument(
        "--bf-method",
        type=str,
        choices=["GET", "POST"],
        default="GET",
        help="HTTP method used with --bf-target-url (default: GET)",
    )
    parser.add_argument(
        "--bf-fuzz-param",
        type=str,
        default="password",
        metavar="PARAM",
        help=(
            "Parameter name to brute-force when using --bf-target-url "
            "(its value is set to FUZZ automatically). Default: password"
        ),
    )
    parser.add_argument(
        "--bf-target-param",
        type=str,
        default="",
        metavar="PARAM",
        help=(
            "Force target parameter in parser/target-url modes. "
            "If omitted, bruteforce target parameter is auto-selected."
        ),
    )
    parser.add_argument(
        "--bf-username-param",
        type=str,
        default="username",
        metavar="PARAM",
        help="Parameter name to override with --bf-username (default: username)",
    )
    parser.add_argument(
        "--bf-username",
        type=str,
        default="admin",
        metavar="VALUE",
        help="Username value used in bruteforce mode (default: admin)",
    )
    parser.add_argument(
        "--bf-extra-params",
        type=str,
        nargs="*",
        default=[],
        metavar="KEY=VALUE",
        help=(
            "Additional fixed parameters sent alongside FUZZ when using --bf-target-url. "
            "Example: --bf-extra-params username=admin Login=Login"
        ),
    )
    parser.add_argument(
        "--sqli-evasion-level",
        type=int,
        choices=[0, 1, 2, 3],
        default=0,
        help=(
            "SQLi evasion intensity: "
            "0=raw only; 1=keyword mixed-case; 2=space as /**/; "
            "3=double URL-encode and %%00 suffix"
        ),
    )
    parser.add_argument(
        "--sqli-time-based",
        action="store_true",
        help="SQLi: include time/stacked payloads (separate set; much slower)",
    )
    parser.add_argument(
        "--sqli-time-max",
        type=int,
        default=0,
        help="SQLi: max time/stacked payloads when --sqli-time-based is set (0=all)",
    )
    parser.add_argument(
        "--target-dbms",
        choices=["mysql", "mssql", "oracle", "postgres", "sqlite", "access", "all"],
        default="all",
        help="selects target dbms for SQLi module (default: all)"
    )
    parser.add_argument(
        "--osci-evasion-level",
        type=int,
        choices=[0, 1, 2, 3],
        default=0,
        help=(
            "OSCi evasion intensity (cumulative per payload pass):"
            "0=raw only; 1=space bypass; "
            "2=+advanced bypass(quotes, semicolons); 3=+double URL-encode"
        ),
    )
    parser.add_argument(
        "--osci-time-based",
        action="store_true",
        help="OSCI: include time-based delay payloads (separate set; much slower)",
    )
    parser.add_argument(
        "--osci-time-max",
        type=int,
        default=0,
        help="OSCI: max time-based payloads when --osci-time-based is set (0=all)",
    )
    parser.add_argument(
        "--target-os",
        choices=["linux", "windows", "all"],
        default="linux",
        help="selects target os for OSCI module (linux runs Unix payloads internally)"
    )
    parser.add_argument(
        "--session-pool-size",
        type=int,
        default=3,
        help="Number of HTTP sessions to use in parallel (default: 3)",
    )
    parser.add_argument(
        "--lfi-evasion-level",
        type=int,
        choices=[0, 1, 2, 3],
        default=1,
        help=(
            "LFI payload mutation level "
            "(0=raw only, 1=url-encoding, 2=double+null-byte, 3=path/case bypass)"
        ),
    )
    parser.add_argument(
        "--ssrf-evasion-level",
        type=int,
        choices=[0, 1, 2],
        default=1,
        help=(
            "SSRF mutation level "
            "(0=off, 1=path encode, 2=path encode + IP obfuscation)"
        ),
    )
    parser.add_argument(
        "--ssrf-oob",
        action="store_true",
        help="SSRF: add OOB/template payloads to the runtime payload set",
    )
    parser.add_argument(
        "--sxss-evasion-level",
        type=int,
        choices=[0, 1, 2, 3],
        default=1,
        help="stored_XSS payload mutation level (0=off/raw, 1=basic WAF bypass, 2=advanced/encoding, 3=obfuscation)"
    )
    parser.add_argument(
        "--exclude-urls",
        nargs="+",
        default=[],
        help=r"크롤링 및 공격에서 제외할 URL 정규식 패턴 목록(예: '/setup\.php' '/admin/.*')"
    )
    parser.add_argument(
        "--rxss-evasion-level",
        type=int,
        choices=[0, 1, 2, 3],
        default=1,
        help="reflected_XSS payload mutation level (0=off/raw, 1=basic WAF bypass, 2=advanced/encoding, 3=obfuscation)"
    )
    parser.add_argument(
        "--local-storage",
        type=str,
        default="{}",
        help="SPA 세션 유지를 위한 Local Storage JSON 데이터 (예: '{\"token\": \"eyJ...\"}')"
    )
    parser.add_argument(
        "--crawl-mode",
        type=str,
        choices=["static", "dynamic", "hybrid"],
        default="hybrid",
        help=(
            "크롤링 방식: static=HTTP 정적만, dynamic=Playwright SPA만, "
            "hybrid=정적+동적 병렬 (기본)"
        ),
    )
    parser.add_argument(
        "--fuzz-csrf",
        action="store_true",
        help=(
            "동적 토큰(CSRF 등)이 감지된 surface도 퍼징합니다. "
            "기본은 CSRF 보호 폼을 제외하며, 활성화 시 매 요청마다 토큰을 갱신해 공격합니다 "
            "(느리고 세션/상태에 영향을 줄 수 있음)."
        ),
    )
    parser.add_argument(
        "--fuzz-auth",
        action="store_true",
        help=(
            "로그인·회원가입·토큰 발급 등 인증 엔드포인트도 퍼징 대상에 포함합니다. "
            "기본은 /login, --login-url 등 인증 surface를 제외합니다 (bruteforce 모드는 예외)."
        ),
    )
    parser.add_argument(
        "--exclude-auth-paths",
        nargs="+",
        default=[],
        help=(
            "추가로 퍼징에서 제외할 인증 URL 경로 조각 "
            "(예: '/rest/user/login' '/api/auth')"
        ),
    )
    parser.add_argument(
        "--graphql-unsafe",
        action="store_true",
        help=(
            "GraphQL Mutation에 대한 공격도 수행합니다. "
            "기본은 안전 모드(Query만 공격)이며, 활성화 시 DB/상태가 변경될 수 있으니 주의."
        ),
    )
    parser.add_argument(
        "--spa-max-routes",
        type=int,
        default=50,
        help="SPA BFS 라우트 탐색 최대 개수 (기본 50)",
    )
    parser.add_argument(
        "--unsafe-click",
        action="store_true",
        help="SPA: submit 외 UI 버튼도 클릭 (커버리지↑, 로그아웃 등 위험↑)",
    )
    return parser


def parse_arguments() -> argparse.Namespace:
    return build_parser().parse_args()

