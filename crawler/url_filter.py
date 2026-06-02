# crawler/url_filter.py

"""
URL 필터
크롤링 대상 URL을 필터링하고 정규화 + SSRF 네트워크 보안 검증 수행
"""

import re
# ✨ [핵심 수정] SSRF 방어를 위한 IP 및 비동기 모듈 추가
import ipaddress
import asyncio
import os
from collections import OrderedDict
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, unquote

from utils.logger import get_logger

logger = get_logger(__name__)


class URLFilter:
    # 하이브리드 크롤러 공유 visited 상한 (LRU 방식으로 오래된 항목 제거)
    MAX_SHARED_VISITED = 50_000

    EXCLUDED_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp',
        '.css', '.js', '.map',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.rar', '.tar', '.gz', '.7z',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
        '.exe', '.dll', '.so', '.dmg', '.apk'
    }

    DEFAULT_EXCLUDED_PATTERNS = [
        r'/logout', r'/signout', r'/sign-out', r'/log-out', r'/delete',
        r'/remove', r'/unsubscribe', r'/deactivate', r'\?.*logout',
        r'\?.*delete', r'\?.*remove',
    ]

    API_PATTERNS = [
        r'/api/', r'/v\d+/', r'/graphql', r'/rest/', r'/ajax/', r'/json/',
        r'/xml/', r'\.json$', r'\.xml$',
    ]

    INTERESTING_PATTERNS = [
        r'/admin', r'/login', r'/register', r'/signup', r'/upload',
        r'/download', r'/search', r'/user', r'/profile', r'/account',
        r'/settings', r'/config', r'/edit', r'/update', r'/create',
        r'/add', r'/submit', r'/process', r'/callback', r'/webhook', r'/redirect',
    ]

    # ✨ [핵심 수정] SSRF 방어용 차단 네트워크 정의 (파서에서 이동)
    BLOCKED_NETWORKS_V4 = (
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("224.0.0.0/4"),
    )

    BLOCKED_NETWORKS_V6 = (
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    )

    def __init__(
            self,
            allowed_domains=None,
            excluded_patterns=None,
            max_url_length=2048,
            max_same_structure=3
    ):
        if allowed_domains is None:
            self.allowed_domains = set()
        else:
            self.allowed_domains = set(allowed_domains)

        self.excluded_domains = set()
        self.max_url_length = max_url_length
        self.allowed_schemes = {'http', 'https'}
        # 정적/동적 크롤러가 공유하는 방문 URL (OrderedDict LRU)
        self.shared_visited: OrderedDict[str, None] = OrderedDict()
        # (path, query_key_names) -> {dom_skeleton_hash: fetch_count}
        self.dom_structure_counts: dict[tuple, dict[str, int]] = {}
        # (path, query_key_names) -> form action tokens already fully parsed
        self.bucket_form_actions: dict[tuple, set[str]] = {}
        self.max_same_structure = max_same_structure

        patterns = self.DEFAULT_EXCLUDED_PATTERNS.copy()
        if excluded_patterns is not None:
            patterns.extend(excluded_patterns)

        self._excluded_regex = [re.compile(p, re.IGNORECASE) for p in patterns]
        self._api_regex = [re.compile(p, re.IGNORECASE) for p in self.API_PATTERNS]
        self._interesting_regex = [re.compile(p, re.IGNORECASE) for p in self.INTERESTING_PATTERNS]
        # 개발/테스트 환경에서만 내부망(예: localhost) 접근을 허용할 수 있는 스위치.
        self.allow_private_targets = os.getenv("WAF_FUZZER_ALLOW_PRIVATE_TARGETS", "").lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

        logger.debug("URL 필터 초기화: 허용 도메인=%s", self.allowed_domains)

    # ✨ [핵심 수정] 네트워크 요청 전 대상 서버 IP 안전성 검증
    async def is_safe_url(self, url: str) -> bool:
        """
        URL 안전성 검증: 스킴 확인 + DNS 해석 + 내부 IP 대역 차단
        SessionManager에서 요청을 보내기 직전에 호출되어 SSRF 공격을 방어합니다.
        """
        try:
            parsed = urlparse(url)
            if parsed.scheme not in self.allowed_schemes:
                return False

            hostname = parsed.hostname
            if not hostname:
                return False

            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            loop = asyncio.get_running_loop()

            # 타임아웃을 걸어 DNS 해석 무한 대기 방지
            addrinfo = await asyncio.wait_for(
                loop.getaddrinfo(hostname, port),
                timeout=3.0,
            )

            for _, _, _, _, sockaddr in addrinfo:
                ip = ipaddress.ip_address(sockaddr[0])

                # IPv4/IPv6에 맞는 네트워크 목록 선택 (TypeError 방지)
                if ip.version == 4:
                    blocked_networks = self.BLOCKED_NETWORKS_V4
                else:
                    blocked_networks = self.BLOCKED_NETWORKS_V6

                if any(ip in network for network in blocked_networks):
                    if self.allow_private_targets:
                        logger.warning(
                            "개발 모드 허용: 내부망/로컬 대상 접근 허용됨 -> %s (IP: %s)",
                            url,
                            ip,
                        )
                        continue
                    logger.warning(f"보안 경고: 내부망 IP 접근 시도 차단됨 -> {url} (IP: {ip})")
                    return False

            return True

        except asyncio.TimeoutError:
            logger.debug(f"DNS 조회 타임아웃: {url}")
            return False
        except OSError as e:
            logger.debug(f"DNS 조회 실패: {url} - {e}")
            return False
        except (ValueError, TypeError) as e:
            logger.debug(f"URL 파싱 오류: {url} - {e}")
            return False
        except Exception as e:
            logger.debug(f"안전성 검증 실패 ({url}): {e}")
            return False

    def mark_visited(self, url: str) -> bool:
        """
        정적/동적 크롤러가 공유하는 visited에 정규화된 URL을 추가.
        반환값: True면 신규 방문(=처리해야 함), False면 이미 다른 엔진이 방문.
        """
        try:
            key = self.normalize_url(url)
        except Exception:
            key = url
        if key in self.shared_visited:
            self.shared_visited.move_to_end(key)
            return False
        self.shared_visited[key] = None
        while len(self.shared_visited) > self.MAX_SHARED_VISITED:
            self.shared_visited.popitem(last=False)
        return True

    def is_visited(self, url: str) -> bool:
        try:
            key = self.normalize_url(url)
        except Exception:
            key = url
        return key in self.shared_visited

    def is_crawlable(self, url: str) -> bool:
        """
        순수 판정만 수행 (url_structure_counts 증가 없음).
        SPA/하이브리드에서 should_crawl을 반복 호출할 때 정적 크롤러 한도를 소모하지 않도록 사용.
        """
        return self._evaluate_crawl_rules(url, count_structure=False)

    def _evaluate_crawl_rules(self, url: str, *, count_structure: bool = False) -> bool:
        """
        Shared crawl eligibility check for static and SPA crawlers.

        count_structure is kept for compatibility with older call sites; the
        current DOM-structure quota is enforced after fetch/parse time.
        """
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()

            if parsed.scheme not in self.allowed_schemes:
                return False

            if len(url) > self.max_url_length:
                return False

            if not self._is_domain_allowed(parsed.netloc):
                return False

            # DVWA: never crawl security.php on any host (avoids toggling session difficulty).
            if path.endswith("/security.php"):
                return False

            if self._has_excluded_extension(parsed.path):
                return False

            if self._matches_excluded_pattern(url):
                return False

            # DOM structure limits are applied after FETCH+parse (see CrawlerEngine).
            return True

        except Exception as e:
            logger.warning("URL 필터링 오류 (%s): %s", url, e)
            return False

    @staticmethod
    def url_bucket(url: str) -> tuple[str, tuple[str, ...]] | None:
        """Bucket key: (path, sorted query param names). None when no query string."""
        parsed = urlparse(url)
        if not parsed.query:
            return None
        query_keys = tuple(sorted(parse_qs(parsed.query).keys()))
        return (parsed.path, query_keys)

    def reset_dom_structure_state(self) -> None:
        """Clear DOM structure counters (new crawl run)."""
        self.dom_structure_counts.clear()
        self.bucket_form_actions.clear()

    @staticmethod
    def structure_bucket(url: str) -> tuple[str, tuple[str, ...]] | None:
        """
        Bucket for DOM/form-action limits.

        Uses query key names when present; otherwise (path, ()) so path-only
        URLs still participate in per-bucket form-action tracking.
        """
        bucket = URLFilter.url_bucket(url)
        if bucket is not None:
            return bucket
        parsed = urlparse(url)
        if not parsed.path:
            return None
        return (parsed.path, ())

    def novel_form_actions(
        self, url: str, form_actions: frozenset[str] | set[str]
    ) -> set[str]:
        """Form actions on this page not yet fully parsed in the URL bucket."""
        bucket = self.structure_bucket(url)
        if bucket is None or not form_actions:
            return set()
        seen = self.bucket_form_actions.setdefault(bucket, set())
        return {action for action in form_actions if action not in seen}

    def mark_form_actions_processed(
        self, url: str, form_actions: frozenset[str] | set[str]
    ) -> None:
        """Record form actions observed during a full page parse."""
        bucket = self.structure_bucket(url)
        if bucket is None or not form_actions:
            return
        self.bucket_form_actions.setdefault(bucket, set()).update(form_actions)

    def page_allows_processing(
        self,
        url: str,
        visit_count: int,
        form_actions: frozenset[str] | set[str],
    ) -> bool:
        """Coarse DOM cap, or at least one never-before-seen form action in bucket."""
        if self.dom_visit_allows_processing(visit_count):
            return True
        return bool(self.novel_form_actions(url, form_actions))

    def record_dom_visit(self, url: str, dom_hash: str) -> int:
        """
        Record a successful page parse for this DOM skeleton.
        Returns the visit count for (url_bucket, dom_hash) after increment.
        """
        try:
            bucket = self.url_bucket(url)
            if bucket is None:
                return 0
            per_dom = self.dom_structure_counts.setdefault(bucket, {})
            per_dom[dom_hash] = per_dom.get(dom_hash, 0) + 1
            return per_dom[dom_hash]
        except Exception as e:
            logger.warning("DOM 구조 방문 기록 오류 (%s): %s", url, e)
            return 0

    def dom_visit_allows_processing(self, visit_count: int) -> bool:
        """True if this visit is within max_same_structure for its DOM hash."""
        if visit_count <= 0:
            return True
        return visit_count <= self.max_same_structure

    def should_crawl(self, url: str) -> bool:
        """Static filters + structure quota check. Does not consume structure quota."""
        return self._evaluate_crawl_rules(url, count_structure=False)

    def _is_domain_allowed(self, domain: str) -> bool:
        if domain in self.excluded_domains:
            return False
        if self.allowed_domains:
            for allowed in self.allowed_domains:
                if domain == allowed or domain.endswith('.' + allowed):
                    return True
            return False
        return True

    def _has_excluded_extension(self, path: str) -> bool:
        path_lower = path.lower()
        for ext in self.EXCLUDED_EXTENSIONS:
            if path_lower.endswith(ext):
                return True
        return False

    def _matches_excluded_pattern(self, url: str) -> bool:
        for regex in self._excluded_regex:
            if regex.search(url):
                return True
        return False

    @staticmethod
    def normalize_url(url: str) -> str:
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            if ':80' in netloc and scheme == 'http':
                netloc = netloc.replace(':80', '')
            elif ':443' in netloc and scheme == 'https':
                netloc = netloc.replace(':443', '')

            path = parsed.path or '/'
            path = re.sub(r'/+', '/', path)
            path = unquote(path)

            query = ''
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                sorted_params = sorted(params.items())
                query_list = []
                for k, v in sorted_params:
                    if len(v) == 1:
                        query_list.append((k, v[0]))
                    else:
                        query_list.append((k, v))
                query = urlencode(query_list, doseq=True)

            fragment = parsed.fragment
            if fragment and not (fragment.startswith('/') or fragment.startswith('!')):
                fragment = ''
            return urlunparse((scheme, netloc, path, '', query, fragment))
        # noinspection PyBroadException
        except Exception as e:
            logger.debug("URL 정규화 실패 (%s): %s", url, e)
            return str(url)

    def is_api_endpoint(self, url: str) -> bool:
        for regex in self._api_regex:
            if regex.search(url):
                return True
        return False

    def is_interesting_url(self, url: str) -> bool:
        for regex in self._interesting_regex:
            if regex.search(url):
                return True
        return False

    def get_url_priority(self, url: str) -> int:
        priority = 5
        if self.is_api_endpoint(url): priority += 3
        if self.is_interesting_url(url): priority += 2
        if '?' in url: priority += 1
        if len(url) > 500: priority -= 1
        return min(10, max(0, priority))

    @staticmethod
    def has_query_params(url: str) -> bool:
        return bool(urlparse(url).query)

    @staticmethod
    def get_query_params(url: str) -> dict:
        try:
            params = parse_qs(urlparse(url).query, keep_blank_values=True)
            return {str(k): str(v[0]) if len(v) == 1 else v for k, v in params.items()}
        # noinspection PyBroadException
        except Exception as e:
            logger.debug("쿼리 파라미터 추출 실패 (%s): %s", url, e)
            return {}

    @staticmethod
    def get_base_url(url: str) -> str:
        try:
            parsed = urlparse(url)
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        # noinspection PyBroadException
        except Exception as e:
            logger.debug("기본 URL 추출 실패 (%s): %s", url, e)
            return str(url).split('?')[0]

    @staticmethod
    def get_path_segments(url: str) -> list:
        try:
            path = urlparse(url).path.strip('/')
            return path.split('/') if path else []
        # noinspection PyBroadException
        except Exception as e:
            logger.debug("경로 세그먼트 추출 실패 (%s): %s", url, e)
            return []

    @staticmethod
    def extract_domain(url: str) -> str:
        try:
            return urlparse(url).netloc.lower()
        # noinspection PyBroadException
        except Exception as e:
            logger.debug("도메인 추출 실패 (%s): %s", url, e)
            return ""

    def is_same_domain(self, url1: str, url2: str) -> bool:
        return self.extract_domain(url1) == self.extract_domain(url2)

    @staticmethod
    def is_same_origin(url1: str, url2: str) -> bool:
        try:
            parsed1 = urlparse(url1)
            parsed2 = urlparse(url2)
            return parsed1.scheme == parsed2.scheme and parsed1.netloc == parsed2.netloc
        # noinspection PyBroadException
        except Exception as e:
            logger.debug("동일 출처 확인 실패: %s", e)
            return False

    def add_allowed_domain(self, domain: str):
        self.allowed_domains.add(domain.lower().strip())

    def add_excluded_domain(self, domain: str):
        self.excluded_domains.add(domain.lower().strip())

    def add_excluded_pattern(self, pattern: str):
        try:
            self._excluded_regex.append(re.compile(str(pattern), re.IGNORECASE))
        except re.error as e:
            logger.debug("잘못된 정규식 패턴 추가 시도 (%s): %s", pattern, e)

    def add_api_pattern(self, pattern: str):
        try:
            self._api_regex.append(re.compile(str(pattern), re.IGNORECASE))
        except re.error as e:
            logger.debug("잘못된 API 정규식 패턴 추가 시도 (%s): %s", pattern, e)