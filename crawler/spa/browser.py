"""Playwright 브라우저 세션: 인증, 쿠키, 페이지 상호작용"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode, urlparse
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from crawler.session_manager import SessionManager


if TYPE_CHECKING:
    from crawler.session_manager import AuthConfig

logger = logging.getLogger(__name__)

AUTH_STORAGE_KEY_HINTS = (
    "token", "access_token", "accesstoken", "jwt", "auth_token",
    "authtoken", "id_token", "bearer", "authorization",
)

NETWORKIDLE_TIMEOUT_MS = 2500

ROUTE_EXTRACT_JS = """() => {
    const routes = new Set();
    const base = document.baseURI;
    const routeAttrNames = new Set([
        'href', 'routerlink', 'router-link', '[routerlink]', '[router-link]',
        'ng-reflect-router-link', 'data-routerlink', 'data-router-link',
        'data-route', 'data-href', 'to', 'ng-href', 'ui-sref'
    ]);
    const clickAttrNames = new Set(['onclick', '(click)', 'ng-click', 'data-click']);
    const safeAdd = (path) => {
        if (!path) return;
        const raw = String(path).trim();
        if (!raw || raw.startsWith('javascript:') || raw.startsWith('mailto:') || raw === '#') return;
        if (raw.startsWith('#') && !(raw.startsWith('#/') || raw.startsWith('#!/'))) return;
        try {
            const u = new URL(raw, base);
            if (u.origin !== window.location.origin) return;
            const frag = (u.hash || '').slice(1);
            if (u.hash && !frag.startsWith('/') && !frag.startsWith('!')) return;
            routes.add(u.href);
        } catch (e) {}
    };
    const revealHiddenMenus = () => {
        const hiddenMenuSelectors = [
            'mat-sidenav', 'mat-drawer', '.mat-sidenav', '.mat-drawer',
            '.mat-drawer-inner-container', '.mat-sidenav-content',
            '.mat-menu-panel', '.cdk-overlay-pane', '.cdk-overlay-container',
            'nav', '[role="navigation"]', '[hidden]', '[aria-hidden="true"]'
        ];
        hiddenMenuSelectors.forEach(selector => {
            document.querySelectorAll(selector).forEach(el => {
                try {
                    el.hidden = false;
                    el.removeAttribute('hidden');
                    el.setAttribute('aria-hidden', 'false');
                    el.setAttribute('aria-expanded', 'true');
                    if ('open' in el) el.open = true;
                    el.style.setProperty('display', 'block', 'important');
                    el.style.setProperty('visibility', 'visible', 'important');
                    el.style.setProperty('opacity', '1', 'important');
                    el.style.setProperty('max-height', 'none', 'important');
                    el.style.setProperty('transform', 'none', 'important');
                    el.style.setProperty('overflow', 'visible', 'important');
                } catch (e) {}
            });
        });
        document.querySelectorAll('details').forEach(el => {
            try { el.open = true; } catch (e) {}
        });
    };
    const extractMatches = (text, patterns) => {
        if (!text) return;
        for (const pattern of patterns) {
            pattern.lastIndex = 0;
            let match;
            while ((match = pattern.exec(text)) !== null) {
                safeAdd(match[1]);
            }
        }
    };
    const parseRouteValue = (value) => {
        if (!value) return;
        const raw = String(value).trim();
        if (!raw) return;
        safeAdd(raw);
        extractMatches(raw, [
            /['"]([^'"]+)['"]/g,
            /\\[\\s*['"]([^'"]+)['"]/g,
        ]);
    };
    const routePatterns = [
        /['"]((?:\\/)?#(?:!\\/|\\/)[^'"\\s]*)['"]/g,
        /['"]((?:\\/)[^'"\\s#]*#(?:!\\/|\\/)[^'"\\s]*)['"]/g,
        /(?:location\\.hash|window\\.location\\.hash|hash)\\s*=\\s*['"](#(?:!\\/|\\/)[^'"\\s]*)['"]/g,
        /(?:navigateByUrl|redirectTo|goTo|visit|push|replace|open)\\s*\\(\\s*['"]([^'"]+)['"]/g,
        /(?:navigate|go)\\s*\\(\\s*\\[\\s*['"]([^'"]+)['"]/g,
        /(?:location\\.(?:href|assign|replace)|window\\.location(?:\\.href)?)\\s*=\\s*['"]([^'"]+)['"]/g,
    ];
    revealHiddenMenus();
    safeAdd(window.location.href);
    safeAdd(window.location.hash || '');
    document.querySelectorAll('a[href], area[href]').forEach(a => safeAdd(a.getAttribute('href')));
    document.querySelectorAll('*').forEach(el => {
        try {
            const attrNames = typeof el.getAttributeNames === 'function' ? el.getAttributeNames() : [];
            attrNames.forEach(attrName => {
                const lowered = String(attrName || '').toLowerCase();
                const value = el.getAttribute(attrName);
                if (routeAttrNames.has(lowered)) parseRouteValue(value);
                if (clickAttrNames.has(lowered) || lowered.includes('click')) {
                    extractMatches(value || '', routePatterns);
                }
            });
        } catch (e) {}
    });
    document.querySelectorAll('[onclick]').forEach(el => {
        const str = el.getAttribute('onclick') || '';
        extractMatches(str, routePatterns);
    });
    document.querySelectorAll('script:not([src])').forEach(script => {
        extractMatches(script.textContent || '', routePatterns);
    });
    return Array.from(routes);
}"""

FILTER_INTERACT_JS = """() => {
    const actionWords = ['search', 'filter', 'apply', 'submit', 'find', 'go', '조회', '검색', '필터'];
    document.querySelectorAll('select').forEach(el => {
        try {
            const validOptions = Array.from(el.options).filter(o => !o.disabled && o.value !== "");
            if (validOptions.length > 0) {
                el.value = validOptions[0].value;
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
            }
        } catch (e) {}
    });
    document.querySelectorAll('button, [role="button"], input[type="button"], input[type="submit"]').forEach(btn => {
        try {
            const text = (btn.innerText || btn.value || btn.getAttribute('aria-label') || '').toLowerCase();
            if (!actionWords.some(w => text.includes(w))) return;
            if (btn.type === 'reset') return;
            btn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
        } catch (e) {}
    });
}"""

FORM_FILL_JS = """() => {
    const fillable = new Set(['', 'text', 'search', 'tel', 'url', 'email', 'number']);
    document.querySelectorAll('input:not([type="hidden"]), textarea').forEach(el => {
        try {
            const t = (el.type || 'text').toLowerCase();
            if (!fillable.has(t)) return;
            if (t === 'email') el.value = 'test@test.com';
            else if (t === 'number') el.value = '1';
            else el.value = 'test_fuzz_payload';
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
        } catch (e) {}
    });
    document.querySelectorAll('select').forEach(el => {
        try {
            const validOptions = Array.from(el.options).filter(o => !o.disabled && o.value !== "");
            if (validOptions.length > 0) {
                el.value = validOptions[0].value;
                el.dispatchEvent(new Event('change', { bubbles: true }));
            }
        } catch (e) {}
    });
}"""

COLLECT_CLICK_TARGETS_JS = """({selector, safe}) => {
    const badWords = [
        'logout', 'signout', 'sign-out', 'log out', 'log-out',
        'delete', 'remove', 'clear', 'reset', 'cancel', 'close',
        '로그아웃', '삭제', '취소', '초기화', '닫기'
    ];
    // SPA에서 자주 쓰이는 전송 버튼 텍스트 추가
    const actionWords = ['submit', 'save', 'write', 'create', 'add', '등록', '작성', '저장', '추가', '결제', '확인'];
    const targets = [];
    const buildSelector = (el) => {
        if (!(el instanceof Element)) return '';
        if (el.id) return `#${CSS.escape(el.id)}`;
        const parts = [];
        let node = el;
        while (node && node instanceof Element && node !== document.documentElement) {
            let part = node.tagName.toLowerCase();
            if (node.classList.length > 0 && node.classList.length <= 3) {
                part += Array.from(node.classList)
                    .slice(0, 3)
                    .map(cls => `.${CSS.escape(cls)}`)
                    .join('');
            }
            const parent = node.parentElement;
            if (parent) {
                const sameTagSiblings = Array.from(parent.children)
                    .filter(child => child.tagName === node.tagName);
                if (sameTagSiblings.length > 1) {
                    part += `:nth-of-type(${sameTagSiblings.indexOf(node) + 1})`;
                }
            }
            parts.unshift(part);
            node = parent;
        }
        return parts.join(' > ');
    };
    document.querySelectorAll(selector).forEach((btn, index) => {
        try {
            if (btn.type === 'reset') return;
            if (btn.closest('a') || btn.hasAttribute('href') ||
                btn.hasAttribute('routerlink') || btn.hasAttribute('to') ||
                btn.hasAttribute('ng-reflect-router-link')) return;
                
            const text = (btn.innerText || btn.value || btn.getAttribute('aria-label') || '').toLowerCase();
            const onclickText = (btn.getAttribute('onclick') || '').toLowerCase();
            
            if (badWords.some(bw => text.includes(bw) || onclickText.includes(bw))) return;
            
            if (safe) {
                const isSubmit = btn.type === 'submit' ||
                                 btn.getAttribute('role') === 'submit' ||
                                 btn.closest('form');
                const hasActionText = actionWords.some(aw => text.includes(aw));
                
                // Form 안에 없더라도 텍스트가 작성/저장 등이라면 클릭 대상에 포함 (SPA 특화)
                if (!isSubmit && !hasActionText) return; 
            }
            const selectorPath = buildSelector(btn);
            if (!selectorPath) return;
            targets.push({
                selector: selectorPath,
                text: text.slice(0, 120),
                type: (btn.type || btn.tagName || '').toLowerCase(),
                index,
            });
        } catch (e) {}
    });

    // Safe mode: click navigation links that expose query params or resource views.
    // Generic patterns: ?key=val links, /view, /edit, /write, /logs (not delete/logout).
    if (safe) {
        const navHints = ['view', 'detail', 'edit', 'write', 'logs', 'log', 'show', 'read'];
        const linkCandidates = [];
        document.querySelectorAll('a[href], area[href]').forEach((a) => {
            try {
                const href = (a.getAttribute('href') || '').trim();
                if (!href || href === '#') return;
                const lowerHref = href.toLowerCase();
                const text = (a.innerText || a.getAttribute('aria-label') || '').toLowerCase();
                if (badWords.some(bw => lowerHref.includes(bw) || text.includes(bw))) return;
                const hasQuery = href.includes('?');
                const hasNavHint = navHints.some(h => lowerHref.includes('/' + h) || lowerHref.includes(h + '?') || text.includes(h));
                if (!hasQuery && !hasNavHint) return;
                linkCandidates.push(a);
            } catch (e) {}
        });

        linkCandidates.slice(0, 14).forEach((a, index) => {
            try {
                const selectorPath = buildSelector(a);
                if (!selectorPath) return;
                const href = (a.getAttribute('href') || '').slice(0, 200);
                targets.push({
                    selector: selectorPath,
                    text: href.toLowerCase(),
                    type: 'link',
                    index: 10000 + index,
                });
            } catch (e) {}
        });
    }
    return targets;
}"""

STORAGE_READ_JS = """() => {
    const out = {};
    for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k) out[k] = localStorage.getItem(k);
    }
    for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        if (k) out['session:' + k] = sessionStorage.getItem(k);
    }
    return out;
}"""


async def wait_for_page_settle(
        page,
        *,
        networkidle_timeout_ms: int = NETWORKIDLE_TIMEOUT_MS,
        context_label: str = "page",
) -> None:
    """
    Prefer event-driven settling over fixed sleeps.
    Short timeout keeps generic scanners moving on sites that keep
    long-polling/WebSocket traffic open forever.
    """
    try:
        await page.wait_for_load_state("networkidle", timeout=networkidle_timeout_ms)
    except PlaywrightTimeoutError:
        logger.debug(
            "[SPA Crawler] networkidle timeout after %s on %s; continuing",
            context_label,
            page.url,
        )
    except Exception as exc:
        logger.debug(
            "[SPA Crawler] networkidle wait failed after %s on %s: %s",
            context_label,
            page.url,
            exc,
        )


def cookies_as_dict(cookies: Any) -> dict[str, str]:
    if hasattr(cookies, "get_dict"):
        return {str(k): str(v) for k, v in cookies.get_dict().items()}
    return {str(k): str(v) for k, v in (cookies or {}).items()}


def merge_playwright_cookies(cookies: Any, browser_cookies: list[dict]) -> dict[str, str]:
    merged = cookies_as_dict(cookies)
    for item in browser_cookies or []:
        name, value = item.get("name"), item.get("value")
        if name is not None and value is not None:
            merged[str(name)] = str(value)
    return merged


def build_playwright_cookies(*, target_url: str, cookies: Any, login_url: str | None = None) -> list[dict]:
    urls: list[str] = []
    for raw in (target_url, login_url):
        if raw and raw.strip().startswith(("http://", "https://")) and raw.strip() not in urls:
            urls.append(raw.strip())
    if not urls:
        logger.warning("[SPA Crawler] No valid URL for cookie seed; skipping initial cookies")
        return []
    entries = []
    for url in urls:
        for name, value in cookies_as_dict(cookies).items():
            entries.append({"name": str(name), "value": str(value), "url": url})
    return entries


def _normalize_hostname(hostname: str | None) -> str:
    return str(hostname or "").strip().lower().lstrip(".")


def cookie_matches_target(engine, cookie: dict[str, Any]) -> bool:
    target_host = _normalize_hostname(getattr(engine, "target_domain", None))
    if not target_host:
        return False
    cookie_domain = _normalize_hostname(cookie.get("domain"))
    if not cookie_domain and cookie.get("url"):
        cookie_domain = _normalize_hostname(urlparse(str(cookie["url"])).hostname)
    if not cookie_domain:
        return False
    return (
        cookie_domain == target_host
        or cookie_domain.endswith(f".{target_host}")
        or target_host.endswith(f".{cookie_domain}")
    )


def filter_cookies_for_target(engine, browser_cookies: list[dict]) -> list[dict]:
    filtered: list[dict] = []
    dropped: list[str] = []
    for cookie in browser_cookies or []:
        if cookie_matches_target(engine, cookie):
            filtered.append(cookie)
            continue
        dropped.append(
            f"{cookie.get('name', '<unnamed>')}@"
            f"{cookie.get('domain') or urlparse(str(cookie.get('url') or '')).hostname or '<unknown>'}"
        )
    if dropped:
        logger.debug("[SPA Crawler] Dropped out-of-scope cookies: %s", ", ".join(dropped[:10]))
    return filtered


def has_auth_storage_trace(local_storage: dict[str, Any]) -> bool:
    for key, raw_value in local_storage.items():
        if not raw_value or str(key).startswith("session:"):
            continue
        if any(hint in str(key).lower() for hint in AUTH_STORAGE_KEY_HINTS):
            if len(str(raw_value).strip()) >= 8:
                return True
    return False


def build_auth_headers(local_storage: dict[str, Any]) -> dict[str, str]:
    for key, raw_value in local_storage.items():
        if not raw_value or str(key).startswith("session:"):
            continue
        if not any(hint in str(key).lower() for hint in AUTH_STORAGE_KEY_HINTS):
            continue
        value = str(raw_value).strip()
        if len(value) < 8:
            continue
        if value.lower().startswith("bearer "):
            return {"Authorization": value}
        return {"Authorization": f"Bearer {value}"}
    return {}


def login_urls_differ(login_url: str, current_url: str) -> bool:
    login = urlparse(login_url)
    current = urlparse(current_url)
    login_base = f"{login.scheme}://{login.netloc}{(login.path or '/').rstrip('/')}"
    current_base = f"{current.scheme}://{current.netloc}{(current.path or '/').rstrip('/')}"
    return current_base != login_base


async def verify_login_success(page, cfg: "AuthConfig", *, local_storage, cookies, pre_login_cookie_names) -> bool:
    try:
        score = 0
        if login_urls_differ(cfg.login_url, page.url):
            score += 1
        if await page.locator('input[type="password"]:visible').count() == 0:
            score += 1
        current_names = set(cookies_as_dict(cookies).keys())
        if (
            build_auth_headers(local_storage)
            or has_auth_storage_trace(local_storage)
            or bool(current_names - pre_login_cookie_names)
        ):
            score += 1
        return score >= 2
    except Exception as exc:
        logger.debug("[SPA Crawler] Login verification failed: %s", exc)
        return False


async def playwright_json_login(engine, page, context) -> bool:
    """application/json 본문으로 로그인 API 호출 (SPA·REST 공통)."""
    if not engine.auth_config:
        return True
    cfg = engine.auth_config
    pre_login_cookie_names = set(cookies_as_dict(engine.cookies).keys())
    login_data = SessionManager.build_login_payload(cfg)
    login_post_data = json.dumps(login_data, ensure_ascii=False)

    from parsers.login_url_inference import iter_login_post_urls

    for post_url in iter_login_post_urls(cfg.login_url):
        try:
            resp = await context.request.post(
                post_url,
                data=login_post_data,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            json_body = None
            try:
                json_body = await resp.json()
            except Exception as exc:
                logger.debug(
                    "[SPA Crawler] JSON login response was not JSON on %s: %s",
                    post_url,
                    exc,
                )

            engine.record_seeded_api(
                method="POST",
                url=post_url,
                post_data=login_post_data,
                req_content_type="application/json",
                status=resp.status,
                content_type=resp.headers.get("content-type", ""),
                source="auth-login-json",
            )

            if resp.status in (404, 405, 415):
                logger.debug(
                    "[SPA Crawler] JSON login skipped for %s (status=%s)",
                    post_url,
                    resp.status,
                )
                continue

            engine.cookies = merge_playwright_cookies(
                engine.cookies,
                filter_cookies_for_target(engine, await context.cookies()),
            )
            for key, value in SessionManager.json_auth_for_local_storage(json_body).items():
                engine.local_storage[key] = value
            if engine.local_storage:
                await page.evaluate(
                    """(items) => {
                        for (const [k, v] of Object.entries(items || {})) {
                            if (k != null && v != null) localStorage.setItem(String(k), String(v));
                        }
                    }""",
                    dict(engine.local_storage),
                )

            await wait_for_page_settle(page, context_label="json login token apply")
            await sync_storage_from_browser(engine, page)
            engine.cookies = merge_playwright_cookies(
                engine.cookies,
                filter_cookies_for_target(engine, await context.cookies()),
            )

            if SessionManager._json_login_failed(json_body):
                continue
            if not (SessionManager._json_login_succeeded(json_body) or resp.ok):
                continue

            if await verify_login_success(
                page,
                cfg,
                local_storage=engine.local_storage,
                cookies=engine.cookies,
                pre_login_cookie_names=pre_login_cookie_names,
            ):
                engine._login_verified = True
                logger.info("[SPA Crawler] Playwright JSON login succeeded: %s", post_url)
                return True
            logger.debug(
                "[SPA Crawler] Playwright JSON login not verified on %s",
                post_url,
            )
        except Exception as e:
            logger.debug("[SPA Crawler] Playwright JSON login failed on %s: %s", post_url, e)
    return False


async def playwright_auth_login(engine, page, context) -> bool:
    """auto/form/json 설정에 따라 폼 로그인 또는 JSON API 로그인."""
    if not engine.auth_config:
        return True
    cfg = engine.auth_config
    html = ""
    try:
        await page.goto(cfg.login_url, wait_until="domcontentloaded", timeout=engine.timeout)
        await wait_for_page_settle(page, context_label="login page load")
        html = await page.content()
    except Exception as e:
        logger.debug("[SPA Crawler] Login page load: %s", e)
        if cfg.login_body_format != "json":
            return False

    body_format = SessionManager._resolve_login_body_format(cfg, html)
    if body_format == "json":
        if await playwright_json_login(engine, page, context):
            return True
        logger.debug("[SPA Crawler] Direct JSON login failed. Falling back to UI form interaction.")

    return await playwright_form_login(engine, page, already_on_login_page=True)


async def playwright_form_login(engine, page, *, already_on_login_page: bool = False) -> bool:
    if not engine.auth_config:
        return True
    cfg = engine.auth_config
    try:
        if not already_on_login_page:
            await page.goto(cfg.login_url, wait_until="domcontentloaded", timeout=engine.timeout)
            await wait_for_page_settle(page, context_label="form login page load")

        # ==========================================
        # 쿠키의 '이름'뿐만 아니라 '값' 전체를 기록하고, 로그인 전 URL을 기록합니다.
        # ==========================================
        pre_login_cookies = cookies_as_dict(engine.cookies)
        pre_login_url = page.url

        login_seed_data = SessionManager.build_login_payload(cfg)
        if cfg.submit_field:
            login_seed_data[cfg.submit_field] = cfg.submit_field
        engine.record_seeded_api(
            method="POST",
            url=cfg.login_url,
            post_data=urlencode(login_seed_data, doseq=True),
            req_content_type="application/x-www-form-urlencoded",
            source="auth-login-form",
        )

        # 1. 범용 아이디 필드 탐색 및 입력
        filled_user = False
        user_locators = []
        if cfg.username_field:
            user_locators.extend([
                f'input[name="{cfg.username_field}" i]',
                f'input[id="{cfg.username_field}" i]',
                f'input[placeholder*="{cfg.username_field}" i]'
            ])
        for ph in ["id", "user", "email", "아이디", "이메일", "계정"]:
            user_locators.append(f'input[placeholder*="{ph}" i]')
        user_locators.extend([
            'input[type="text"]:not([hidden])',
            'input[type="email"]:not([hidden])',
            'input:not([type]):not([hidden])'
        ])
        for selector in user_locators:
            loc = page.locator(selector)
            count = await loc.count()
            for i in range(count):
                element = loc.nth(i)
                if await element.is_visible():
                    await element.fill(cfg.username, timeout=2000)
                    filled_user = True
                    break
            if filled_user:
                break
        if not filled_user:
            logger.warning("[SPA Crawler] Login username field not found on %s", cfg.login_url)
            return False

        # 2. 범용 비밀번호 필드 탐색 및 입력
        filled_pw = False
        pw_locators = []
        if cfg.password_field:
            pw_locators.extend([
                f'input[name="{cfg.password_field}" i]',
                f'input[id="{cfg.password_field}" i]'
            ])
        pw_locators.append('input[type="password"]:not([hidden])')
        for selector in pw_locators:
            loc = page.locator(selector)
            count = await loc.count()
            for i in range(count):
                element = loc.nth(i)
                if await element.is_visible():
                    await element.fill(cfg.password, timeout=2000)
                    filled_pw = True
                    break
            if filled_pw:
                break
        if not filled_pw:
            logger.warning("[SPA Crawler] Login password field not found on %s", cfg.login_url)
            return False

        # 3. 범용 로그인 버튼 클릭 및 제출
        submitted = False
        submit_selectors = []
        if cfg.submit_field:
            submit_selectors.extend([
                f'button[name="{cfg.submit_field}" i]',
                f'input[name="{cfg.submit_field}" i]',
                f'button:has-text("{cfg.submit_field}")'
            ])
        submit_selectors.extend([
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Login" i)',
            'button:has-text("로그인")',
            'button:has-text("Sign in" i)',
            '.login-btn', '.submit-btn'
        ])
        for selector in submit_selectors:
            loc = page.locator(selector)
            count = await loc.count()
            for i in range(count):
                btn = loc.nth(i)
                if await btn.is_visible():
                    await btn.click(timeout=3000)
                    submitted = True
                    break
            if submitted:
                break
        if not submitted:
            await page.keyboard.press("Enter")

        # ==========================================
        #  로그인 결과 검증 및 토큰 수집 (범용 SPA 처리 강화)
        # ==========================================
        # SPA(React) 특성상 백엔드 통신 후 화면 전환(history.push)까지 미세한 딜레이가 발생하므로 강제 대기 추가
        await page.wait_for_timeout(1500)
        await wait_for_page_settle(page, context_label="form login submit")
        await sync_storage_from_browser(engine, page)

        engine.cookies = merge_playwright_cookies(
            engine.cookies,
            filter_cookies_for_target(engine, await page.context.cookies()),
        )

        login_success = False
        post_login_cookies = cookies_as_dict(engine.cookies)

        # [범용 검증 1] URL 리다이렉션 감지 (SPA 라우팅 포함)
        if page.url != pre_login_url and "login" not in page.url.lower():
            login_success = True

        # [범용 검증 2] 세션 롤링 감지 (쿠키 이름이 같아도 '값'이 바뀌었으면 성공으로 간주)
        if not login_success:
            for name, value in post_login_cookies.items():
                if name not in pre_login_cookies or pre_login_cookies[name] != value:
                    login_success = True
                    break

        # [범용 검증 3] 기존 검증 로직으로 Fallback (로컬 스토리지에 JWT 토큰이 생겼는지 등)
        if not login_success:
            login_success = await verify_login_success(
                page, cfg,
                local_storage=engine.local_storage,
                cookies=engine.cookies,
                pre_login_cookie_names=set(pre_login_cookies.keys()),
            )

        if login_success:
            engine._login_verified = True
            logger.info("[SPA Crawler] Playwright form login succeeded: %s", cfg.login_url)
            return True

        logger.warning("[SPA Crawler] Playwright form login not verified (2-of-3): %s", cfg.login_url)
        return False

    except Exception as e:
        logger.warning("[SPA Crawler] Playwright form login failed on %s: %s", cfg.login_url, e)
        return False


async def sync_storage_from_browser(engine, page) -> None:
    try:
        storage = await page.evaluate(STORAGE_READ_JS)
        for key, value in storage.items():
            if value and key not in engine.local_storage:
                engine.local_storage[key] = value
    except Exception as e:
        logger.debug("[SPA Crawler] Storage sync failed: %s", e)


async def sync_cookies_from_context(engine, context) -> None:
    try:
        pw_cookies = await context.cookies()
        if pw_cookies:
            filtered = filter_cookies_for_target(engine, pw_cookies)
            engine.cookies = merge_playwright_cookies(engine.cookies, filtered)
    except Exception as e:
        logger.debug("[SPA Crawler] Cookie sync failed: %s", e)


async def recover_page_after_click(engine, page, original_url: str) -> None:
    if page.url == original_url:
        return
    try:
        await page.go_back(wait_until="domcontentloaded", timeout=3000)
        if page.url == original_url:
            return
    except Exception as exc:
        logger.debug("[SPA Crawler] go_back recovery failed from %s: %s", page.url, exc)
    try:
        await page.goto(original_url, wait_until="domcontentloaded", timeout=engine.timeout)
    except Exception as exc:
        logger.debug("[SPA Crawler] goto recovery failed for %s: %s", original_url, exc)


async def click_targets_sequentially(engine, page, targets: list[dict[str, Any]], original_url: str) -> None:
    from crawler.spa.capture import is_in_scope

    for target in targets:
        selector = str(target.get("selector") or "").strip()
        if not selector:
            continue
        if page.url != original_url:
            await recover_page_after_click(engine, page, original_url)
        locator = page.locator(selector).first
        try:
            if await locator.count() == 0:
                logger.debug("[SPA Crawler] Click target disappeared before click: %s", selector)
                continue
        except Exception as exc:
            logger.debug("[SPA Crawler] Click target lookup failed for %s: %s", selector, exc)
            continue

        try:
            await locator.scroll_into_view_if_needed(timeout=1000)
        except Exception as exc:
            logger.debug("[SPA Crawler] Click target scroll failed for %s: %s", selector, exc)

        clicked = False
        try:
            async with page.expect_navigation(wait_until="domcontentloaded", timeout=1500):
                await locator.click(timeout=1500)
            clicked = True
        except PlaywrightTimeoutError:
            clicked = True
        except Exception as exc:
            logger.debug("[SPA Crawler] Sequential click failed for %s: %s", selector, exc)
            continue

        if not clicked:
            continue

        try:
            await wait_for_page_settle(page, context_label=f"click:{selector}")
        except Exception as exc:
            logger.debug("[SPA Crawler] Post-click wait failed for %s: %s", selector, exc)

        current_url = page.url
        if current_url != original_url:
            if not is_in_scope(engine, current_url):
                logger.debug(
                    "[SPA Crawler] Click target left scope (%s -> %s); restoring original page",
                    original_url,
                    current_url,
                )
            else:
                logger.debug(
                    "[SPA Crawler] Click target navigated away from seed route (%s -> %s); restoring original page",
                    original_url,
                    current_url,
                )
            await recover_page_after_click(engine, page, original_url)


async def interact_and_submit(engine, page) -> None:
    from crawler.spa.capture import extract_dom_links, is_in_scope

    # 1. 스크롤 및 호버 액션 (유지)
    try:
        for _ in range(2):
            await page.evaluate("window.scrollBy(0, window.innerHeight);")
            await page.wait_for_timeout(300)
        await page.evaluate("""() => {
            document.querySelectorAll('[role="button"], [aria-haspopup="true"], .dropdown').forEach(el => {
                try { el.dispatchEvent(new MouseEvent('mouseover', {bubbles: true})); } catch (e) { }
            });
        }""")
    except Exception as exc:
        logger.debug("[SPA Crawler] Pre-click hover/scroll interaction failed: %s", exc)

    # 오리지널 URL을 상단에서 저장
    original_url = page.url

    # 2. 파일 업로드 (유지)
    try:
        for el in await page.locator('input[type="file"]:visible').all():
            try:
                await el.set_input_files(engine.dummy_file_path, timeout=1000)
                await el.evaluate("el => el.dispatchEvent(new Event('change', { bubbles: true }))")
            except Exception as exc:
                logger.debug("[SPA Crawler] File input injection skipped: %s", exc)
    except Exception as e:
        logger.debug("[SPA Crawler] File upload injection failed: %s", e)

    # ==========================================
    # [수정 1] 폼 필드 입력 및 "입력 여부" 추적
    # ==========================================
    filled_any = False
    try:
        text_inputs = page.locator(
            'input:not([type="hidden"]):not([type="button"]):not([type="submit"]):not([type="checkbox"]):not([type="radio"]), textarea')
        count = await text_inputs.count()
        for i in range(count):
            loc = text_inputs.nth(i)
            if await loc.is_visible():
                input_type = await loc.get_attribute("type")
                if input_type == "email":
                    await loc.fill("test@test.com", timeout=1000)
                elif input_type == "number":
                    await loc.fill("1", timeout=1000)
                else:
                    await loc.fill("test_fuzz_payload", timeout=1000)
                filled_any = True  # 폼에 값을 채웠음을 기록

        checks = page.locator('input[type="checkbox"], input[type="radio"]')
        count = await checks.count()
        for i in range(count):
            loc = checks.nth(i)
            if await loc.is_visible() and not await loc.is_checked():
                await loc.check(timeout=1000)
    except Exception as exc:
        logger.debug(f"[SPA Crawler] Native Playwright fill failed: {exc}")

    try:
        await page.evaluate(FORM_FILL_JS)
        await page.evaluate(FILTER_INTERACT_JS)
        await page.wait_for_timeout(500)
    except Exception as e:
        logger.debug(f"[SPA Crawler] Form fill failed: {e}")

    # ==========================================
    # [수정 2] 범용 SPA 폼 전송 보장 및 1.5초 대기 (핵심)
    # ==========================================
    if filled_any:
        try:
            # 1순위: 엔터키 강제 전송
            await text_inputs.first.press("Enter", timeout=1000)

            # [가장 중요] React/Vue가 백그라운드(fetch)로 데이터를 보내고
            # 스캐너 엔진(capture_core)이 패킷을 낚아챌 수 있도록 1.5초를 기다려 줍니다!
            await page.wait_for_timeout(1500)

            if page.url != original_url:
                from crawler.spa.dom_form_capture import register_route_query_params_from_url

                register_route_query_params_from_url(engine, page.url)
                await page.wait_for_timeout(500)
                await page.goto(original_url, wait_until="domcontentloaded", timeout=engine.timeout)
                await page.wait_for_timeout(1000)

            # 2순위: 등록/작성/저장 버튼 찾아서 직접 누르기
            submit_btns = page.locator(
                'button[type="submit"], input[type="submit"], button:has-text("작성"), button:has-text("등록"), button:has-text("저장"), button:has-text("추가"), button:has-text("Submit"), button:has-text("Save")')
            count = await submit_btns.count()
            for i in range(count):
                btn = submit_btns.nth(i)
                if await btn.is_visible():
                    await btn.click(timeout=1500)
                    await page.wait_for_timeout(1500)  # 버튼 누른 후에도 1.5초 통신 대기
                    if page.url != original_url:
                        from crawler.spa.dom_form_capture import register_route_query_params_from_url

                        register_route_query_params_from_url(engine, page.url)
                        await page.wait_for_timeout(500)
                        await page.goto(original_url, wait_until="domcontentloaded", timeout=engine.timeout)
                        await page.wait_for_timeout(1000)
                        break
        except Exception as e:
            logger.debug(f"[SPA Crawler] Form submit action failed: {e}")

    # ==========================================
    # [수정 3] 일반 UI 버튼 클릭 (들여쓰기 오류 수정)
    # ==========================================
    # (이전 코드에서는 이 부분이 except 안에 갇혀있어서 실행이 안 됐습니다)
    click_selector = (
        'form button, form input[type="submit"], button:not([type="reset"]), [role="button"]'
        if engine.safe_click
        else 'button:not([type="reset"], [role="button"]), .btn'
    )

    try:
        click_targets = await page.evaluate(
            COLLECT_CLICK_TARGETS_JS,
            {"selector": click_selector, "safe": engine.safe_click},
        )
        await click_targets_sequentially(engine, page, click_targets or [], original_url)
    except Exception as e:
        logger.debug("[SPA Crawler] Sequential click collection/execution failed: %s", e)

    # 4. 크롤링 범위 이탈 시 복구
    try:
        current_url = page.url
        if current_url != original_url and not is_in_scope(engine, current_url):
            try:
                await page.go_back(wait_until="domcontentloaded", timeout=3000)
            except Exception as exc:
                logger.debug("[SPA Crawler] Post-click go_back failed from %s: %s", current_url, exc)
                await page.goto(original_url, wait_until="domcontentloaded", timeout=engine.timeout)
    except Exception as e:
        logger.debug("[SPA Crawler] Post-click recovery failed: %s", e)

    # 최종 DOM에서 새로운 링크 추출
    await extract_dom_links(engine, page)