"""
핵심 데이터 모델 (Unified Core Models)
Team A (Crawler/Parser) + Team B (Fuzzer) 통합 운영 버전
"""

from __future__ import annotations
import re
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Awaitable, Callable, Dict

logger = logging.getLogger(__name__)


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class ParamLocation(str, Enum):
    QUERY = "query"
    BODY_FORM = "body_form"
    BODY_JSON = "body_json"
    HEADER = "header"
    COOKIE = "cookie"
    PATH = "path"


class CrawlStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


# ============================================================
# 핵심 서비스 DTO (추가된 TokenDetector & PageData)
# ============================================================

class TokenDetector:
    """동적 토큰(CSRF, Nonce 등) 감지기"""
    TOKEN_KEYWORDS = [
        'csrf', 'xsrf', 'token', 'nonce', 'auth', '_token', 'authenticity',
        'verification', 'user_token', 'form_token', 'request_token', 'anti_csrf', '_csrf'
    ]

    HASH_PATTERNS = [
        r'^[a-fA-F0-9]{32}$', r'^[a-fA-F0-9]{40}$', r'^[a-fA-F0-9]{64}$',
        r'^[A-Za-z0-9+/]{20,}={0,2}$', r'^[a-fA-F0-9-]{36}$', r'^[a-zA-Z0-9_-]{16,}$'
    ]

    COMMON_WORDS = ['submit', 'login', 'search', 'password', 'username', 'button', 'reset', 'cancel']

    @classmethod
    def is_token_name(cls, name: str) -> bool:
        if not name: return False
        return any(keyword in name.lower() for keyword in cls.TOKEN_KEYWORDS)

    @classmethod
    def is_token_value(cls, value: str) -> bool:
        if not value or len(value) < 16: return False
        if value.isdigit(): return False
        if value.lower() in cls.COMMON_WORDS: return False
        return any(re.match(pattern, value) for pattern in cls.HASH_PATTERNS)

    @classmethod
    def detect(cls, name: str, value: str, input_type: str = None) -> bool:
        normalized_value = str(value).strip() if value is not None else ""

        # 값이 비어있는 경우에는 동적 토큰으로 보지 않는다.
        if not normalized_value:
            return False

        if cls.is_token_name(name): return True
        if input_type == 'hidden' and cls.is_token_value(normalized_value): return True
        if cls.is_token_value(normalized_value):
            name_lower = name.lower() if name else ""
            weak_keywords = ['key', 'hash', 'secret', 'verify', 'check', 'valid']
            if any(kw in name_lower for kw in weak_keywords):
                return True
        return False


class PageData:
    def __init__(
            self,
            url: str,
            html: str,
            depth: int = 0,
            headers: dict[str, str] | None = None,
            cookies: dict[str, str] | None = None,
            dynamic_tokens: Dict[str, str] | None = None,
            server_info: dict[str, str] | None = None,  # 🚀 서버 정보 필드 추가
            soup: Any = None
    ):
        self.url = url
        self.html = html
        self.depth = depth
        self.headers = headers if headers is not None else {}
        self.cookies = cookies if cookies is not None else {}
        self.dynamic_tokens = dynamic_tokens if dynamic_tokens is not None else {}
        self.server_info = server_info if server_info is not None else {}
        self.soup = soup  # 파서로부터 전달받은 soup 저장

    def __repr__(self) -> str:
        return (f"PageData(url='{self.url}', "
                f"depth={self.depth}, "
                f"headers={len(self.headers)}, "
                f"cookies={len(self.cookies)}, "
                f"tokens={len(self.dynamic_tokens)})")


@dataclass(slots=True)
class AttackSurface:
    """
    크롤러/파서 → 퍼저 전달용 공격 표면 DTO
    """
    url: str
    method: HttpMethod = HttpMethod.GET
    param_location: ParamLocation = ParamLocation.QUERY
    parameters: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    dynamic_tokens: Dict[str, str] = field(default_factory=dict)
    server_info: dict[str, str] = field(default_factory=dict)
    source_url: str | None = None
    description: str | None = None
    depth: int = 0
    content_type: str | None = None
    graphql_arg_types: Dict[str, str] = field(default_factory=dict)
    parameter_confidence: Dict[str, str] = field(default_factory=dict)

    def get_id(self) -> str:
        """고유 식별자 생성"""
        params_str = str(sorted(self.parameters.keys()))
        raw = f"{self.url}:{self.method.value}:{self.param_location.value}:{params_str}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            'id': self.get_id(),
            'url': self.url,
            'method': self.method.value,
            'param_location': self.param_location.value,
            'parameters': self.parameters,
            'headers': self.headers,
            'cookies': self.cookies,
            'dynamic_tokens': self.dynamic_tokens,
            'server_info': self.server_info,
            'source_url': self.source_url,
            'description': self.description,
            'depth': self.depth,
            'content_type': self.content_type,
            'graphql_arg_types': self.graphql_arg_types,
            'parameter_confidence': self.parameter_confidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackSurface:
        return cls(
            url=data['url'],
            method=HttpMethod(data.get('method', 'GET')),
            param_location=ParamLocation(data.get('param_location', 'query')),
            parameters=data.get('parameters', {}),
            headers=data.get('headers', {}),
            cookies=data.get('cookies', {}),
            dynamic_tokens=_normalize_dynamic_tokens(data.get('dynamic_tokens', {})),
            server_info=data.get('server_info', {}),
            source_url=data.get('source_url'),
            description=data.get('description'),
            depth=data.get('depth', 0),
            content_type=data.get('content_type'),
            graphql_arg_types=_normalize_graphql_arg_types(data.get('graphql_arg_types', {})),
            parameter_confidence=_normalize_parameter_confidence(data.get('parameter_confidence', {})),
        )


# ============================================================
# Team B - Fuzzer 전용 데이터 모델 (누락되었던 부분 복구)
# ============================================================

@dataclass(slots=True, frozen=True)
class Payload:
    """Structured payload metadata used by payload provider/reporter."""
    value: str
    attack_type: str
    risk_level: str


@dataclass(slots=True, frozen=True)
class FuzzingTask:
    """One concrete fuzzing unit generated from a surface."""
    surface: AttackSurface
    target_param: str
    payload: Payload


# ============================================================
# Team A - Crawler / Parser 전용 데이터 모델
# ============================================================

@dataclass(slots=True)
class CrawlTask:
    """크롤링 작업 단위"""
    url: str
    depth: int = 0
    parent_url: str | None = None
    retry_count: int = 0
    priority: int = 0  # 높을수록 우선
    created_at: datetime = field(default_factory=datetime.now)

    def __lt__(self, other: CrawlTask) -> bool:
        return self.priority > other.priority

    def to_dict(self) -> dict[str, Any]:
        return {
            'url': self.url, 'depth': self.depth, 'parent_url': self.parent_url,
            'retry_count': self.retry_count, 'priority': self.priority,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CrawlTask:
        return cls(
            url=data['url'],
            depth=data.get('depth', 0),
            parent_url=data.get('parent_url'),
            retry_count=data.get('retry_count', 0),
            priority=data.get('priority', 0),
        )


@dataclass(slots=True)
class CrawlResult:
    """크롤러 → 파서 전달 데이터"""
    url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    body: str
    content_type: str
    response_time: float
    depth: int
    parent_url: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)
    cookies: dict[str, str] = field(default_factory=dict)
    content_length: int = 0
    is_dynamic: bool = False
    redirect_chain: list[str] = field(default_factory=list)

    def get_hash(self) -> str:
        return hashlib.md5(self.body.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            'url': self.url,
            'final_url': self.final_url,
            'status_code': self.status_code,
            'content_type': self.content_type,
            'response_time': self.response_time,
            'depth': self.depth,
            'parent_url': self.parent_url,
            'timestamp': self.timestamp.isoformat(),
            'content_length': self.content_length,
            'is_dynamic': self.is_dynamic,
            'body_hash': self.get_hash(),
        }


@dataclass
class CrawlStats:
    """크롤링 통계 관리 (누락된 메서드 복구)"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    skipped_requests: int = 0

    total_forms_found: int = 0
    total_links_found: int = 0
    total_apis_found: int = 0
    total_attack_surfaces: int = 0

    bytes_downloaded: int = 0

    start_time: datetime | None = None
    end_time: datetime | None = None

    errors_by_type: dict[str, int] = field(default_factory=dict)
    status_codes: dict[int, int] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            return (datetime.now() - self.start_time).total_seconds()
        return 0.0

    @property
    def requests_per_second(self) -> float:
        return self.total_requests / self.duration if self.duration > 0 else 0.0

    @property
    def success_rate(self) -> float:
        return (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0.0

    def record_error(self, error_type: str) -> None:
        self.errors_by_type[error_type] = self.errors_by_type.get(error_type, 0) + 1

    def record_status(self, status_code: int) -> None:
        self.status_codes[status_code] = self.status_codes.get(status_code, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'skipped_requests': self.skipped_requests,
            'success_rate': f"{self.success_rate:.2f}%",
            'duration': f"{self.duration:.2f}s",
            'requests_per_second': f"{self.requests_per_second:.2f}",
            'bytes_downloaded': self.bytes_downloaded,
            'forms_found': self.total_forms_found,
            'links_found': self.total_links_found,
            'attack_surfaces': self.total_attack_surfaces,
            'errors_by_type': self.errors_by_type,
            'status_codes': self.status_codes,
        }


# ============================================================
# 팀 A → 팀 B 전달용 콜백 타입
# ============================================================

# AttackSurface를 받는 콜백 타입
SurfaceCallback = Callable[[AttackSurface], Awaitable[None] | None]


def _normalize_dynamic_tokens(raw_tokens: Any) -> Dict[str, str]:
    if isinstance(raw_tokens, dict):
        return {str(k): str(v) for k, v in raw_tokens.items()}
    if isinstance(raw_tokens, list):
        normalized: Dict[str, str] = {}
        for token in raw_tokens:
            token_str = str(token)
            if "=" in token_str:
                key, value = token_str.split("=", 1)
                normalized[str(key)] = str(value)
        return normalized
    return {}


def _normalize_graphql_arg_types(raw_arg_types: Any) -> Dict[str, str]:
    if isinstance(raw_arg_types, dict):
        return {str(k): str(v) for k, v in raw_arg_types.items()}
    return {}


def _normalize_parameter_confidence(raw_confidence: Any) -> Dict[str, str]:
    if not isinstance(raw_confidence, dict):
        return {}
    normalized: Dict[str, str] = {}
    for raw_key, raw_level in raw_confidence.items():
        key = str(raw_key).strip()
        level = str(raw_level).strip().lower()
        if not key:
            continue
        if level not in {"high", "medium", "low"}:
            continue
        normalized[key] = level
    return normalized