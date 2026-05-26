# crawler/engine.py

import asyncio
from urllib.parse import urljoin, urlparse
from datetime import datetime
from contextlib import asynccontextmanager
from core.models import PageData, TokenDetector, CrawlStats
from parsers.html_parser import AsyncHTMLParser
from crawler.dom_skeleton import collect_form_actions, skeleton_hash
from crawler.path_trace import CrawlPathTrace, build_crawl_path_log_filename
from crawler.session_manager import SessionManager
from crawler.url_filter import URLFilter
from utils.logger import get_logger

# Temporary: set prefix to None to disable crawl path txt export.
CRAWL_PATH_LOG_PREFIX = "crawl_path_debug"

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
        # ✨ [수정] models.py의 통합 CrawlStats 사용
        self._stats = CrawlStats(start_time=datetime.now())
        self._shutdown = asyncio.Event()
        self._path_trace: CrawlPathTrace | None = None
        self.crawl_path_log_path: str | None = None

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

        self._reset_state(start_url)
        self._setup_domain_filter(start_url)

        if self._path_trace:
            await self._path_trace.log("SEED_ENQUEUE", url=start_url, depth=0)
        await self._queue.put((start_url, 0))

        async with self._session_context():
            await self._run_workers()

        # ✨ [핵심 수정] 모든 워커가 종료된 후, 파서 컨슈머에게 종료 신호 전송
        await self.queue_manager.add_page(None)
        logger.info("[Engine] 파서 종료 신호(Sentinel) 전송 완료")

        self._stats.end_time = datetime.now()
        if self._path_trace:
            await self._path_trace.summary(
                visited=len(self._visited),
                queued_remaining=self._queue.qsize(),
                stats=self._stats.to_dict(),
            )
        self._log_summary()
        return self._stats

    def _reset_state(self, start_url: str = "") -> None:
        self._visited.clear()
        self.url_filter.reset_dom_structure_state()
        self._stats = CrawlStats(start_time=datetime.now())
        self._shutdown.clear()
        self._queue = asyncio.Queue()
        self._path_trace = None
        self.crawl_path_log_path = None
        if CRAWL_PATH_LOG_PREFIX and start_url:
            self.crawl_path_log_path = build_crawl_path_log_filename(CRAWL_PATH_LOG_PREFIX)
            self._path_trace = CrawlPathTrace(self.crawl_path_log_path)
            self._path_trace.reset(start_url)

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
                    if self._path_trace:
                        await self._path_trace.log(
                            "WORKER_STOP_MAX_URLS",
                            url=url,
                            depth=depth,
                            worker_id=worker_id,
                            detail=f"successful_requests={self._stats.successful_requests}",
                        )
                    self._shutdown.set()
                    break

                if self._path_trace:
                    await self._path_trace.log(
                        "DEQUEUE",
                        url=url,
                        depth=depth,
                        worker_id=worker_id,
                        detail=f"queue_size={self._queue.qsize()}",
                    )
                await self._process_url(url, depth, worker_id=worker_id)
                await asyncio.sleep(self.config.delay)

            except asyncio.TimeoutError:
                if self._queue.empty():
                    if self._path_trace:
                        await self._path_trace.log(
                            "WORKER_EXIT_QUEUE_EMPTY",
                            worker_id=worker_id,
                            detail=f"successful_requests={self._stats.successful_requests}",
                        )
                    break
            except Exception as e:
                logger.error("워커 %d 오류: %s", worker_id, e)

    def _should_continue_crawling(self):
        return not self._shutdown.is_set() and self._stats.successful_requests < self.config.max_urls

    async def _process_url(self, url, depth, *, worker_id: int | None = None):
        url = self.url_filter.normalize_url(url)
        if url in self._visited:
            if self._path_trace:
                await self._path_trace.log(
                    "SKIP_ALREADY_VISITED",
                    url=url,
                    depth=depth,
                    worker_id=worker_id,
                )
            return
        if not self.url_filter.should_crawl(url):
            if self._path_trace:
                await self._path_trace.log(
                    "SKIP_FILTER",
                    url=url,
                    depth=depth,
                    worker_id=worker_id,
                )
            return

        self._visited.add(url)
        self._stats.total_requests += 1
        logger.debug("[%d] %s (depth=%d)", self._stats.total_requests, url, depth)
        if self._path_trace:
            await self._path_trace.log(
                "FETCH",
                url=url,
                depth=depth,
                worker_id=worker_id,
            )

        try:
            response = await self.session_manager.get(url, timeout=self.config.timeout)
            if response:
                status = int(response.get("status", 0) or 0)
                if 200 <= status < 300:
                    if self._path_trace:
                        await self._path_trace.log(
                            "FETCH_OK",
                            url=url,
                            depth=depth,
                            worker_id=worker_id,
                            detail=f"status={status}",
                        )
                    await self._process_response(
                        response, url, depth, worker_id=worker_id
                    )
                else:
                    if self._path_trace:
                        await self._path_trace.log(
                            "FETCH_HTTP_ERROR",
                            url=url,
                            depth=depth,
                            worker_id=worker_id,
                            detail=f"status={status}",
                        )
                    self._stats.failed_requests += 1
                    self._stats.record_status(status)
            else:
                if self._path_trace:
                    await self._path_trace.log(
                        "FETCH_NO_RESPONSE",
                        url=url,
                        depth=depth,
                        worker_id=worker_id,
                    )
                self._stats.failed_requests += 1
        except Exception as e:
            logger.error("처리 실패 (%s): %s", url, e)
            if self._path_trace:
                await self._path_trace.log(
                    "FETCH_EXCEPTION",
                    url=url,
                    depth=depth,
                    worker_id=worker_id,
                    detail=str(e),
                )
            self._stats.failed_requests += 1
            self._stats.record_error(type(e).__name__)

    def _fingerprint_server(self, headers: dict, cookies: dict, url: str) -> dict:
        info = {"web_server": "Unknown", "language": "Unknown"}

        headers_lower = {k.lower(): v for k, v in headers.items()}
        server_header = headers_lower.get("server", "").lower()
        powered_by = headers_lower.get("x-powered-by", "").lower()

        # 1. 웹 서버 추론 (헤더 기반)
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

        # 2. 개발 언어 추론 (교차 검증: A. 헤더 -> B. 쿠키 -> C. URL)
        # A. 헤더 확인
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

        # B. 쿠키 확인 (헤더에서 못 찾았을 경우)
        if info["language"] == "Unknown":
            if "PHPSESSID" in cookies:
                info["language"] = "PHP"
            elif "ASPSESSIONID" in cookies:
                info["language"] = "ASP.NET"
            elif "JSESSIONID" in cookies:
                info["language"] = "Java"
            elif "connect.sid" in cookies:  # Express.js 기본 세션
                info["language"] = "Node.js"
            elif "_session_id" in cookies:  # Ruby on Rails 기본 세션
                info["language"] = "Ruby"
            elif "CFID" in cookies or "CFTOKEN" in cookies:  # Adobe ColdFusion
                info["language"] = "ColdFusion"

        # C. URL 확장자 확인 (쿠키로도 못 찾았을 경우)
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

    async def _process_response(self, response, url, depth, *, worker_id: int | None = None):
        html = response.get("text", "")
        final_url = str(response.get("url", url))
        headers = response.get("headers", {})
        cookies = self.session_manager.get_cookies()

        #  서버 환경 탐지 실행 (헤더, 쿠키, URL 모두 전달)
        server_info = self._fingerprint_server(headers, cookies, final_url)

        loop = asyncio.get_running_loop()

        parse_result = await loop.run_in_executor(
            None, AsyncHTMLParser.parse_html_string, html, final_url
        )

        if not parse_result.get("success"):
            logger.warning("파싱 건너뜀 (%s): %s", final_url, parse_result.get("error"))
            if self._path_trace:
                await self._path_trace.log(
                    "SKIP_PARSE_FAILED",
                    url=final_url,
                    depth=depth,
                    worker_id=worker_id,
                    detail=str(parse_result.get("error")),
                )
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
        novel_actions = self.url_filter.novel_form_actions(final_url, form_actions)
        process_page = self.url_filter.page_allows_processing(
            final_url, visit_count, form_actions
        )
        if self._path_trace:
            novel_detail = ""
            if novel_actions:
                novel_detail = f" novel_actions={sorted(novel_actions)}"
            await self._path_trace.log(
                "DOM_STRUCTURE",
                url=final_url,
                depth=depth,
                worker_id=worker_id,
                detail=(
                    f"hash={dom_hash} visit={visit_count} process={process_page}"
                    f"{novel_detail}"
                ),
            )
        if not process_page:
            if self._path_trace:
                await self._path_trace.log(
                    "SKIP_DOM_STRUCTURE_LIMIT",
                    url=final_url,
                    depth=depth,
                    worker_id=worker_id,
                    detail=f"hash={dom_hash} max={self.url_filter.max_same_structure}",
                )
            self._stats.record_status(response.get("status", 0))
            return

        self.url_filter.mark_form_actions_processed(final_url, form_actions)
        self._stats.successful_requests += 1
        self._stats.record_status(response.get("status", 0))

        # 🚀 PageData 생성 시 server_info 전달
        page = PageData(
            url=final_url,
            html=html,
            depth=depth,
            headers=headers,
            cookies=cookies,
            server_info=server_info,  # 추가된 부분
            soup=soup
        )

        # ✨ 무거운 DOM 순회 로직을 스레드 풀로 위임하기 위한 내부 함수
        def _extract_data_sync(soup_obj, base_url):
            tokens = {}
            next_urls = set()
            forms_found = 0
            links_found = 0

            # 폼 & 동적 토큰 추출
            for form in soup_obj.find_all("form"):
                forms_found += 1
                for input_field in form.find_all(["input", "textarea", "select"]):
                    name = input_field.get("name", "").strip()
                    if not name: continue
                    value = input_field.get("value", "")
                    input_type = input_field.get("type", "text")
                    if TokenDetector.detect(name, value, input_type):
                        tokens[name] = value

            # 다음 크롤링 대상 URL 추출
            for a in soup_obj.find_all("a", href=True):
                links_found += 1
                next_urls.add(urljoin(base_url, a['href']))
            for form in soup_obj.find_all("form", action=True):
                next_urls.add(urljoin(base_url, form['action']))

            return tokens, next_urls, forms_found, links_found

        # ✨ 스레드 풀에서 DOM 순회 작업을 실행하여 메인 루프 블로킹 방지
        tokens, next_urls, forms_cnt, links_cnt = await loop.run_in_executor(
            None, _extract_data_sync, soup, final_url
        )

        # 3. 추출된 통계 업데이트 및 토큰 병합
        self._stats.total_forms_found += forms_cnt
        self._stats.total_links_found += links_cnt
        page.dynamic_tokens.update(tokens)

        # 4. 비동기 큐 매니저로 전달
        await self.queue_manager.add_page(page)

        # 5. 다음 크롤링 대상 URL 추가
        if depth < self.config.max_depth:
            for n_url in next_urls:
                child_depth = depth + 1
                normalized_child = self.url_filter.normalize_url(n_url)
                if normalized_child in self._visited:
                    if self._path_trace:
                        await self._path_trace.log(
                            "SKIP_ENQUEUE_VISITED",
                            url=normalized_child,
                            depth=child_depth,
                            worker_id=worker_id,
                            detail=f"from={final_url}",
                        )
                    continue
                if not self.url_filter.should_crawl(n_url):
                    if self._path_trace:
                        await self._path_trace.log(
                            "SKIP_ENQUEUE_FILTER",
                            url=normalized_child,
                            depth=child_depth,
                            worker_id=worker_id,
                            detail=f"from={final_url}",
                        )
                    continue
                if self._path_trace:
                    await self._path_trace.log(
                        "ENQUEUE",
                        url=normalized_child,
                        depth=child_depth,
                        worker_id=worker_id,
                        detail=f"from={final_url}",
                    )
                await self._queue.put((n_url, child_depth))
        elif self._path_trace and next_urls:
            await self._path_trace.log(
                "SKIP_ENQUEUE_MAX_DEPTH",
                url=final_url,
                depth=depth,
                worker_id=worker_id,
                detail=f"child_candidates={len(next_urls)}",
            )

    def _log_summary(self):
        logger.info("========== 크롤링 종료 ==========")
        stats_dict = self._stats.to_dict()
        logger.info(
            "요청 성공: %s, 폼 발견: %s, 링크 발견: %s, 소요 시간: %s",
            stats_dict['successful_requests'],
            stats_dict['forms_found'],
            stats_dict['links_found'],
            stats_dict['duration']
        )

    def get_stats(self):
        return self._stats.to_dict()