# crawler/session_manager.py

import asyncio
import json
import re
from typing import Optional, Any
from urllib.parse import urljoin

import aiohttp
from bs4 import BeautifulSoup

from utils.logger import get_logger

logger = get_logger(__name__)


class AuthConfig:
    """인증 설정"""

    def __init__(
            self,
            login_url: str,
            username: str,
            password: str,
            username_field: str = "username",
            password_field: str = "password",
            extra_fields: Optional[dict] = None,
            success_indicator: Optional[str] = None,
            failure_indicator: Optional[str] = None,
            csrf_token_name: Optional[str] = "user_token",
            submit_field: Optional[str] = "Login",
            login_body_format: str = "auto",
    ):
        self.login_url = login_url
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.extra_fields = extra_fields or {}
        self.success_indicator = success_indicator
        self.failure_indicator = failure_indicator
        self.csrf_token_name = csrf_token_name
        self.submit_field = submit_field
        self.login_body_format = (login_body_format or "auto").strip().lower()


class SessionManager:
    """HTTP 세션 관리자"""

    # ✨ [핵심 수정] 의존성 주입: url_filter 파라미터 추가
    def __init__(self, proxy=None, verify_ssl=False, custom_headers=None, url_filter=None):
        self._session = None
        self._cookies = {}
        self._headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

        if custom_headers:
            self._headers.update(custom_headers)

        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self._authenticated = False

        # ✨ [핵심 수정] URLFilter 인스턴스 저장
        self.url_filter = url_filter

    async def create_session(self):
        """세션 생성"""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=10,
                limit_per_host=5,
                ssl=self.verify_ssl
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                cookie_jar=aiohttp.CookieJar(unsafe=True)
            )
            logger.debug("새 세션 생성됨")

    async def close(self):
        """세션 종료"""
        if self._session and not self._session.closed:
            await self._session.close()
            self._authenticated = False
            logger.debug("세션 종료됨")

    @staticmethod
    def _get_safe_attr(element: Any, attr_name: str) -> str:
        """bs4 요소에서 속성값을 안전하게 문자열로 추출 (PyCharm Type Guard)"""
        if element is None or not hasattr(element, 'get'):
            return ""

        raw_val = element.get(attr_name)
        if isinstance(raw_val, list):
            return str(raw_val[0]) if raw_val else ""
        elif raw_val is not None:
            return str(raw_val)
        return ""

    @staticmethod
    def _extract_csrf_token(html: str, token_name: str) -> Optional[str]:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            token_input = soup.find('input', {'name': token_name})

            val = SessionManager._get_safe_attr(token_input, 'value')
            if val:
                return val

            common_names = [
                'user_token', 'csrf_token', '_token', 'token',
                'csrf', '_csrf_token', 'authenticity_token', '_csrf',
            ]
            for name in common_names:
                token_input = soup.find('input', {'name': name})
                val = SessionManager._get_safe_attr(token_input, 'value')
                if val:
                    return val

            hidden_inputs = soup.find_all('input', {'type': 'hidden'})
            for inp in hidden_inputs:
                name = SessionManager._get_safe_attr(inp, 'name').lower()
                if 'token' in name or 'csrf' in name:
                    val = SessionManager._get_safe_attr(inp, 'value')
                    if val:
                        return val
        except Exception as e:
            logger.warning("CSRF 토큰 추출 실패: %s", e)
        return None

    @staticmethod
    def _extract_meta_redirect(html: str, base_url: str) -> Optional[str]:
        try:
            match = re.search(
                r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?\d+;?\s*url=([^"\'\s>]+)',
                html,
                re.IGNORECASE
            )
            if match:
                redirect_url = match.group(1)
                if not redirect_url.startswith('http'):
                    redirect_url = urljoin(base_url, redirect_url)
                return redirect_url
        except Exception as e:
            logger.debug("메타 리다이렉트 추출 실패: %s", e)
        return None

    @staticmethod
    def _detect_json_login(html: str) -> bool:
        """로그인 페이지가 fetch/XHR 로 JSON 본문을 보내는지 휴리스틱 판별."""
        if not html:
            return False
        lower = html.lower()
        json_hints = (
            "application/json",
            "json.stringify",
            '"content-type": "application/json"',
            "'content-type': 'application/json'",
            "content-type: application/json",
        )
        if not any(hint in lower for hint in json_hints):
            return False
        try:
            soup = BeautifulSoup(html, "html.parser")
            forms = soup.find_all("form")
            if not forms:
                return True
            password_inputs = soup.find_all("input", {"type": "password"})
            if password_inputs and any(hint in lower for hint in json_hints):
                return True
        except Exception:
            pass
        return False

    @staticmethod
    def _resolve_login_body_format(auth_config: AuthConfig, login_page_html: str) -> str:
        fmt = auth_config.login_body_format
        if fmt in ("json", "form"):
            return fmt
        if SessionManager._detect_json_login(login_page_html):
            return "json"
        return "form"

    @staticmethod
    def _json_login_failed(payload: Any) -> bool:
        if not isinstance(payload, dict):
            return False
        if payload.get("success") is False or payload.get("ok") is False:
            return True
        error = payload.get("error") or payload.get("message") or payload.get("detail")
        if isinstance(error, str) and error.strip():
            lowered = error.lower()
            failure_words = ("invalid", "fail", "wrong", "incorrect", "denied", "unauthorized")
            return any(word in lowered for word in failure_words)
        return False

    @staticmethod
    def _json_login_succeeded(payload: Any) -> bool:
        if not isinstance(payload, dict):
            return False
        if payload.get("success") is True or payload.get("ok") is True:
            return True
        if SessionManager.extract_token_from_json(payload):
            return True
        nested = payload.get("data")
        if isinstance(nested, dict):
            return SessionManager._json_login_succeeded(nested)
        return False

    @staticmethod
    def build_login_payload(auth_config: AuthConfig, *, csrf_token: Optional[str] = None) -> dict:
        login_data = {
            auth_config.username_field: auth_config.username,
            auth_config.password_field: auth_config.password,
        }
        if csrf_token and auth_config.csrf_token_name:
            login_data[auth_config.csrf_token_name] = csrf_token
        login_data.update(auth_config.extra_fields)
        return login_data

    @staticmethod
    def extract_token_from_json(payload: Any) -> Optional[tuple[str, str]]:
        """JSON 로그인 응답에서 (storage_key, token) 추출."""
        token_keys = ("token", "access_token", "accessToken", "jwt", "id_token", "session", "sessionId")
        if isinstance(payload, dict):
            for key in token_keys:
                raw = payload.get(key)
                if isinstance(raw, str) and len(raw.strip()) >= 8:
                    return key, raw.strip()
            for key, value in payload.items():
                extracted = SessionManager.extract_token_from_json(value)
                if extracted:
                    nested_key, token = extracted
                    return f"{key}.{nested_key}", token
        elif isinstance(payload, list):
            for idx, item in enumerate(payload):
                extracted = SessionManager.extract_token_from_json(item)
                if extracted:
                    nested_key, token = extracted
                    return f"[{idx}].{nested_key}", token
        return None

    def apply_json_auth_token(self, json_body: Any) -> None:
        """JSON 응답 토큰을 Authorization 헤더에 반영."""
        extracted = self.extract_token_from_json(json_body)
        if not extracted:
            return
        _, token = extracted
        if token.lower().startswith("bearer "):
            self._headers["Authorization"] = token
        else:
            self._headers["Authorization"] = f"Bearer {token}"

    @staticmethod
    def json_auth_for_local_storage(json_body: Any) -> dict[str, str]:
        extracted = SessionManager.extract_token_from_json(json_body)
        if not extracted:
            return {}
        key, token = extracted
        return {key: token}

    async def login(self, auth_config: AuthConfig) -> bool:
        if self._session is None:
            await self.create_session()

        forced_json = auth_config.login_body_format == "json"
        logger.info("로그인 시도: %s", auth_config.login_url)
        login_page = await self.get(auth_config.login_url)

        if not login_page:
            if forced_json:
                logger.info(
                    "JSON 로그인: 로그인 URL GET 실패 — API 직접 POST만 시도합니다: %s",
                    auth_config.login_url,
                )
                html = ""
            else:
                logger.warning(
                    "로그인 페이지 GET 실패(타임아웃·연결 거부·DNS 등): %s",
                    auth_config.login_url,
                )
                return False
        else:
            html = login_page.get("text", "")

        body_format = self._resolve_login_body_format(auth_config, html)
        csrf_token = None
        if body_format != "json" and auth_config.csrf_token_name:
            csrf_token = self._extract_csrf_token(html, auth_config.csrf_token_name)
            if not csrf_token:
                logger.warning(
                    "CSRF 필드(%s) 값을 찾지 못했습니다. 사이트가 DVWA와 다르면 "
                    "--csrf-field 를 비우거나 실제 hidden 필드명으로 맞춰 보세요.",
                    auth_config.csrf_token_name,
                )

        login_data = self.build_login_payload(auth_config, csrf_token=csrf_token)

        if body_format == "json":
            logger.info("JSON 본문으로 로그인 POST: %s", auth_config.login_url)
            response = await self.post(
                auth_config.login_url,
                json_data=login_data,
                headers={"Accept": "application/json", "Content-Type": "application/json"},
            )
        else:
            if auth_config.submit_field:
                login_data[auth_config.submit_field] = auth_config.submit_field
            response = await self.post(
                auth_config.login_url,
                data=login_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

        if not response:
            logger.warning(
                "로그인 POST 응답 없음(네트워크 오류 등): %s",
                auth_config.login_url,
            )
            return False

        text = response.get("text", "")
        final_url = response.get("url", "")
        status = response.get("status")
        json_body = response.get("json")

        if body_format == "json" and self._json_login_failed(json_body):
            logger.warning("JSON 로그인 API가 실패 응답을 반환했습니다.")
            return False

        if body_format == "json":
            has_session_cookie = bool(response.get("cookies"))
            if self._json_login_succeeded(json_body) or (
                status in (200, 201, 204) and has_session_cookie
            ):
                self.apply_json_auth_token(json_body)
                self._authenticated = True
                logger.info("JSON 로그인 성공 (status=%s)", status)
                return True

        redirect_url = self._extract_meta_redirect(text, auth_config.login_url)
        if redirect_url:
            response = await self.get(redirect_url)
            if response:
                text = response.get("text", "")
                final_url = response.get("url", "")

        if auth_config.failure_indicator and auth_config.failure_indicator in text:
            return False

        if auth_config.success_indicator:
            if auth_config.success_indicator in text or auth_config.success_indicator.lower() in text.lower():
                self._authenticated = True
                return True

        if 'login' not in final_url.lower():
            self._authenticated = True
            return True

        if response and response.get("status") in [200, 302]:
            self._authenticated = True
            return True

        logger.warning(
            "로그인 실패로 판단: status=%s final_url=%s",
            status,
            final_url,
        )
        return False

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    def get_cookies(self) -> dict:
        cookies = {}
        cookies.update(self._cookies)
        if self._session and self._session.cookie_jar:
            for cookie in self._session.cookie_jar:
                cookies[cookie.key] = cookie.value
        return cookies

    def set_cookies(self, cookies: dict):
        if cookies:
            self._cookies.update(cookies)

    def set_header(self, name: str, value: str):
        self._headers[name] = value

    def set_headers(self, headers: dict):
        if headers:
            self._headers.update(headers)

    @staticmethod
    def is_api_content_type(content_type: Optional[str]) -> bool:
        if not content_type:
            return False
        api_types = ['application/json', 'application/xml', 'application/x-www-form-urlencoded', 'text/json',
                     'text/xml']

        ct = str(content_type).lower()
        return any(api_type in ct for api_type in api_types)

    async def _request(self, method: str, url: str, timeout: int = 10, allow_redirects: bool = True,
                       max_retries: int = 3, headers: Optional[dict] = None, **kwargs) -> Optional[dict]:

        # ✨ [핵심 수정] 1차 방어: HTTP 요청을 보내기 전 목표 URL의 안전성(SSRF) 검사
        if self.url_filter:
            if not await self.url_filter.is_safe_url(url):
                logger.warning(f"SSRF 보안 정책에 의해 사전 차단된 URL 시도: {url}")
                return None

        if self._session is None:
            await self.create_session()

        assert self._session is not None, "Session was not properly initialized"

        request_timeout = aiohttp.ClientTimeout(total=timeout)
        request_headers = self._headers.copy()
        if headers is not None:
            request_headers.update(headers)

        for attempt in range(max_retries):
            try:
                async with self._session.request(
                        method=method,
                        url=url,
                        timeout=request_timeout,
                        allow_redirects=allow_redirects,
                        headers=request_headers,
                        proxy=self.proxy,
                        **kwargs
                ) as response:

                    # ✨ [핵심 수정] 2차 방어: Open Redirect를 악용한 SSRF 우회 검사
                    final_url = str(response.url)
                    if url != final_url and self.url_filter:
                        if not await self.url_filter.is_safe_url(final_url):
                            logger.warning(f"리다이렉트 최종 목적지가 SSRF 정책에 의해 차단됨: {final_url}")
                            return None

                    json_data = None
                    try:
                        content_type = response.content_type
                        if self.is_api_content_type(content_type):
                            try:
                                json_data = await response.json()
                                text = json.dumps(json_data, ensure_ascii=False)
                            except json.JSONDecodeError:
                                text = await response.text()
                        else:
                            text = await response.text()
                    except UnicodeDecodeError:
                        text = ""
                    except Exception as e:
                        logger.debug("응답 데이터 텍스트 변환 실패: %s", e)
                        text = ""

                    for cookie in response.cookies.values():
                        self._cookies[cookie.key] = cookie.value

                    response_cookies = {cookie.key: cookie.value for cookie in response.cookies.values()}

                    return {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "cookies": response_cookies,
                        "url": final_url,  # 리다이렉트가 반영된 최종 URL 전달
                        "text": text,
                        "json": json_data,
                        "content_type": response.content_type,
                        "method": method,
                        "history": [str(r.url) for r in response.history]
                    }
            except asyncio.TimeoutError:
                pass
            except aiohttp.ClientError:
                pass
            except Exception as e:
                logger.debug("요청 처리 중 예기치 않은 오류 발생: %s", e)
                break

            if attempt < max_retries - 1:
                await asyncio.sleep((2 ** attempt) * 0.5)

        return None

    async def get(self, url: str, **kwargs) -> Optional[dict]:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, data: Optional[dict] = None, json_data: Optional[dict] = None,
                   headers: Optional[dict] = None, **kwargs) -> Optional[dict]:
        if json_data is not None:
            return await self._request("POST", url, json=json_data, headers=headers, **kwargs)
        return await self._request("POST", url, data=data, headers=headers, **kwargs)

    async def put(self, url: str, data: Optional[dict] = None, json_data: Optional[dict] = None,
                  headers: Optional[dict] = None, **kwargs) -> Optional[dict]:
        if json_data is not None:
            return await self._request("PUT", url, json=json_data, headers=headers, **kwargs)
        return await self._request("PUT", url, data=data, headers=headers, **kwargs)

    async def delete(self, url: str, **kwargs) -> Optional[dict]:
        return await self._request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> Optional[dict]:
        return await self._request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> Optional[dict]:
        return await self._request("OPTIONS", url, **kwargs)

    async def detect_methods(self, url: str) -> list:
        allowed_methods = []
        try:
            response = await self.options(url, max_retries=1, timeout=5)
            if response:
                allow_header = response.get("headers", {}).get("Allow", "")
                if allow_header:
                    return [m.strip().upper() for m in allow_header.split(",")]
                cors_header = response.get("headers", {}).get("Access-Control-Allow-Methods", "")
                if cors_header:
                    return [m.strip().upper() for m in cors_header.split(",")]
        except Exception as e:
            logger.debug("OPTIONS 메서드 확인 실패: %s", e)

        test_methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]
        for method in test_methods:
            try:
                response = await self._request(method=method, url=url, max_retries=1, timeout=3, allow_redirects=False)
                if response and response.get("status", 0) != 405:
                    allowed_methods.append(method)
            except Exception as e:
                logger.debug("단일 메서드(%s) 테스트 중 오류: %s", method, e)
                continue
        return allowed_methods if allowed_methods else ["GET"]