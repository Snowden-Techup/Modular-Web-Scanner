# crawler/engine.py

import asyncio
from urllib.parse import urljoin, urlparse
from datetime import datetime
from contextlib import asynccontextmanager
from core.models import PageData, TokenDetector, CrawlStats
from parsers.html_parser import AsyncHTMLParser
from crawler.dom_skeleton import collect_form_actions, skeleton_hash
from crawler.session_manager import SessionManager
from crawler.url_filter import URLFilter
from utils.logger import get_logger

logger = get_logger(__name__)


class CrawlConfig:
    """크롤링 설정 클래스"""

    def __init__(self, max_depth=3, max_urls=250, delay=0.5, timeout=10, workers=5):
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.delay = delay
        self.timeout = timeout
        self.workers = workers


class CrawlerEngine:
    """개선된 웹 크롤러 엔진 (성능 및 모델 통합 버전)"""

    def __init__(self, queue_manager, config=None):
        self.queue_manager = queue_manager
        self.config = config or CrawlConfig()
        self.url_filter = URLFilter()

        # SessionManager 생성 시 url_filter를 주입하여 SSRF 방어벽 연결
        self.session_manager = SessionManager(url_filter=self.url_filter)
        self._external_session = False

        self._visited = set()
        self._queue = asyncio.Queue()
        self._stats = CrawlStats(start_time=datetime.now())
        self._shutdown = asyncio.Event()

    def set_session(self, session_manager):
        self.session_manager = session_manager
        self.session_manager.url_filter = self.url_filter
        self._external_session = True
        logger.info("외부 세션 연결됨")

    @asynccontextmanager
    async def _session_context(self):
        if not self._external_session:
            await self.session_manager.create_session()
        try:
            yield
        finally:
            if not self._external_session:
                await self.session_manager.close()

    async def start(self, start_url):
        logger.info("========== 크롤링 시작 ==========")
        logger.info("대상: %s", start_url)

        self._reset_state()
        self._setup_domain_filter(start_url)
        await self._queue.put((start_url, 0))

        async with self._session_context():
            await self._run_workers()

        await self.queue_manager.add_page(None)
        logger.info("[Engine] 파서 종료 신호(Sentinel) 전송 완료")

        self._stats.end_time = datetime.now()
        self._log_summary()
        return self._stats

    def _reset_state(self) -> None:
        self._visited.clear()
        self.url_filter.reset_dom_structure_state()
        self._stats = CrawlStats(start_time=datetime.now())
        self._shutdown.clear()
        self._queue = asyncio.Queue()

    def _setup_domain_filter(self, start_url):
        domain = urlparse(start_url).netloc
        self.url_filter.add_allowed_domain(domain)

    async def _run_workers(self):
        self._workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self.config.workers)
        ]
        try:
            await asyncio.gather(*self._workers, return_exceptions=True)
        finally:
            await self._cleanup_workers()

    async def _cleanup_workers(self):
        self._shutdown.set()
        for worker in self._workers:
            if not worker.done():
                worker.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    async def _worker(self, worker_id):
        while not self._shutdown.is_set():
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                url, depth = item

                if not self._should_continue_crawling():
                    self._shutdown.set()
                    break

                await self._process_url(url, depth)
                await asyncio.sleep(self.config.delay)

            except asyncio.TimeoutError:
                if self._queue.empty():
                    break
            except Exception as e:
                logger.error("워커 %d 오류: %s", worker_id, e)

    def _should_continue_crawling(self):
        return not self._shutdown.is_set() and self._stats.successful_requests < self.config.max_urls

    async def _process_url(self, url, depth):
        url = self.url_filter.normalize_url(url)
        if url in self._visited:
            return

        # 공유 visited(다른 크롤러도 방문 기록) 확인하여 하이브리드 중복 방문 차단
        if not self.url_filter.mark_visited(url):
            self._visited.add(url)
            logger.debug("[Engine] 공유 visited 히트, 스킵: %s", url)
            return

        self._visited.add(url)
        self._stats.total_requests += 1
        logger.debug("[%d] %s (depth=%d)", self._stats.total_requests, url, depth)

        try:
            response = await self.session_manager.get(url, timeout=self.config.timeout)
            if response:
                status = int(response.get("status", 0) or 0)
                if 200 <= status < 300:
                    await self._process_response(response, url, depth)
                else:
                    self._stats.failed_requests += 1
                    self._stats.record_status(status)
            else:
                self._stats.failed_requests += 1
        except Exception as e:
            logger.error("처리 실패 (%s): %s", url, e)
            self._stats.failed_requests += 1
            self._stats.record_error(type(e).__name__)

    def _fingerprint_server(self, headers: dict, cookies: dict, url: str) -> dict:
        info = {"web_server": "Unknown", "language": "Unknown"}

        headers_lower = {k.lower(): v for k, v in headers.items()}
        server_header = headers_lower.get("server", "").lower()
        powered_by = headers_lower.get("x-powered-by", "").lower()

        if "apache" in server_header:
            info["web_server"] = "Apache"
        elif "nginx" in server_header:
            info["web_server"] = "Nginx"
        elif "iis" in server_header:
            info["web_server"] = "IIS"
        elif "express" in powered_by or "express" in server_header:
            info["web_server"] = "Express"
        elif "cloudflare" in server_header:
            info["web_server"] = "Cloudflare"
        elif "litespeed" in server_header:
            info["web_server"] = "LiteSpeed"
        elif "caddy" in server_header:
            info["web_server"] = "Caddy"
        elif "werkzeug" in server_header or "gunicorn" in server_header:
            info["web_server"] = "Gunicorn/Werkzeug"

        if "php" in powered_by or "php" in server_header:
            info["language"] = "PHP"
        elif "asp.net" in powered_by or "iis" in server_header:
            info["language"] = "ASP.NET"
        elif "jsp" in powered_by or "tomcat" in server_header or "java" in powered_by:
            info["language"] = "Java"
        elif "node" in powered_by or "express" in powered_by or "express" in server_header:
            info["language"] = "Node.js"
        elif "python" in powered_by or "werkzeug" in server_header or "gunicorn" in server_header:
            info["language"] = "Python"
        elif "ruby" in powered_by or "passenger" in server_header:
            info["language"] = "Ruby"

        if info["language"] == "Unknown":
            if "PHPSESSID" in cookies:
                info["language"] = "PHP"
            elif "ASPSESSIONID" in cookies:
                info["language"] = "ASP.NET"
            elif "JSESSIONID" in cookies:
                info["language"] = "Java"
            elif "connect.sid" in cookies:
                info["language"] = "Node.js"
            elif "_session_id" in cookies:
                info["language"] = "Ruby"
            elif "CFID" in cookies or "CFTOKEN" in cookies:
                info["language"] = "ColdFusion"

        url_lower = url.lower()
        if info["language"] == "Unknown":
            if ".php" in url_lower:
                info["language"] = "PHP"
            elif ".asp" in url_lower or ".aspx" in url_lower:
                info["language"] = "ASP.NET"
            elif ".jsp" in url_lower or ".do" in url_lower or ".action" in url_lower:
                info["language"] = "Java"
            elif ".rb" in url_lower:
                info["language"] = "Ruby"
            elif ".py" in url_lower:
                info["language"] = "Python"
            elif ".cfm" in url_lower:
                info["language"] = "ColdFusion"

        return info

    async def _process_response(self, response, url, depth):
        html = response.get("text", "")
        final_url = str(response.get("url", url))
        headers = response.get("headers", {})
        cookies = self.session_manager.get_cookies()

        server_info = self._fingerprint_server(headers, cookies, final_url)

        loop = asyncio.get_running_loop()

        parse_result = await loop.run_in_executor(
            None, AsyncHTMLParser.parse_html_string, html, final_url
        )

        if not parse_result.get("success"):
            logger.warning("파싱 건너뜀 (%s): %s", final_url, parse_result.get("error"))
            self._stats.failed_requests += 1
            return

        soup = parse_result.get("soup")
        if soup is None:
            return

        dom_hash, form_actions = await asyncio.gather(
            loop.run_in_executor(None, skeleton_hash, soup, final_url),
            loop.run_in_executor(None, collect_form_actions, soup, final_url),
        )
        visit_count = self.url_filter.record_dom_visit(final_url, dom_hash)
        process_page = self.url_filter.page_allows_processing(
            final_url, visit_count, form_actions
        )
        if not process_page:
            self._stats.record_status(response.get("status", 0))
            return

        self.url_filter.mark_form_actions_processed(final_url, form_actions)
        self._stats.successful_requests += 1
        self._stats.record_status(response.get("status", 0))

        page = PageData(
            url=final_url,
            html=html,
            depth=depth,
            headers=headers,
            cookies=cookies,
            server_info=server_info,
            soup=soup
        )

        def _extract_data_sync(soup_obj, base_url):
            tokens = {}
            next_urls = set()
            forms_found = 0
            links_found = 0

            for form in soup_obj.find_all("form"):
                forms_found += 1
                for input_field in form.find_all(["input", "textarea", "select"]):
                    name = input_field.get("name", "").strip()
                    if not name:
                        continue
                    value = input_field.get("value", "")
                    input_type = input_field.get("type", "text")
                    if TokenDetector.detect(name, value, input_type):
                        tokens[name] = value

            for a in soup_obj.find_all("a", href=True):
                links_found += 1
                next_urls.add(urljoin(base_url, a['href']))
            for form in soup_obj.find_all("form", action=True):
                next_urls.add(urljoin(base_url, form['action']))

            return tokens, next_urls, forms_found, links_found

        tokens, next_urls, forms_cnt, links_cnt = await loop.run_in_executor(
            None, _extract_data_sync, soup, final_url
        )

        self._stats.total_forms_found += forms_cnt
        self._stats.total_links_found += links_cnt
        page.dynamic_tokens.update(tokens)

        await self.queue_manager.add_page(page)

        if depth < self.config.max_depth:
            for n_url in next_urls:
                child_depth = depth + 1
                normalized_child = self.url_filter.normalize_url(n_url)
                if normalized_child in self._visited:
                    continue
                if not self.url_filter.should_crawl(n_url):
                    continue
                await self._queue.put((n_url, child_depth))

    def _log_summary(self):
        logger.info("========== 정적 크롤링 종료 ==========")
        stats_dict = self._stats.to_dict()
        logger.info(
            "[Static] 요청 성공: %s, 폼 발견: %s, 링크 발견: %s, 소요 시간: %s",
            stats_dict['successful_requests'],
            stats_dict['forms_found'],
            stats_dict['links_found'],
            stats_dict['duration']
        )

    def get_stats(self):
        return self._stats.to_dict()