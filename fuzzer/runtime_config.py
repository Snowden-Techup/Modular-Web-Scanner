from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Any

# Central defaults — override via env vars or FuzzerEngine(runtime_config=...).
DEFAULT_MAX_RESPONSE_BODY_BYTES = 5 * 1024 * 1024
DEFAULT_CACHE_MODULE_PAYLOADS = True

# Stored XSS defaults (override via FUZZER_STORED_XSS_* env vars).
DEFAULT_STORED_XSS_ANALYZE_BODY_BYTES = 512 * 1024
DEFAULT_STORED_XSS_VERIFY_BODY_BYTES = 512 * 1024
DEFAULT_STORED_XSS_DOM_WINDOW_BYTES = 64 * 1024
DEFAULT_STORED_XSS_BASELINE_BODY_BYTES = 512 * 1024
DEFAULT_STORED_XSS_ABSOLUTE_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_STORED_XSS_VERIFY_CONCURRENCY = 1
DEFAULT_STORED_XSS_VERIFY_MAX_URLS = 8
DEFAULT_STORED_XSS_LIST_POLL_MAX = 3
DEFAULT_STORED_XSS_LOCK_MAP_SIZE = 64
DEFAULT_STORED_XSS_MAX_CONCURRENT = 10
DEFAULT_STORED_XSS_MAX_WORKERS = 2
DEFAULT_STORED_XSS_VERIFY_DETAIL_MAX = 4
DEFAULT_STORED_XSS_PROGRESS_BLOCKS_MAX = 32
DEFAULT_STORED_XSS_WAF_COMPARE_BYTES = 1000
DEFAULT_STORED_XSS_USE_DOM_PARSER = True

# LFI defaults (FUZZER_LFI_* env vars).
DEFAULT_LFI_ANALYZE_BODY_BYTES = 512 * 1024
DEFAULT_LFI_ABSOLUTE_MAX_BYTES = 2 * 1024 * 1024

# File upload defaults (FUZZER_FILE_UPLOAD_* env vars).
DEFAULT_FILE_UPLOAD_ANALYZE_BODY_BYTES = 512 * 1024
DEFAULT_FILE_UPLOAD_VERIFY_BODY_BYTES = 256 * 1024
DEFAULT_FILE_UPLOAD_DISCOVERY_BODY_BYTES = 512 * 1024
DEFAULT_FILE_UPLOAD_ABSOLUTE_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_FILE_UPLOAD_VERIFY_MAX_URLS = 12
DEFAULT_FILE_UPLOAD_VERIFY_CONCURRENCY = 1
DEFAULT_FILE_UPLOAD_VERIFY_FETCH_CONCURRENCY = 4
DEFAULT_FILE_UPLOAD_MAX_PAGE_PROBES = 6
DEFAULT_FILE_UPLOAD_MAX_POST_DETAILS = 3
DEFAULT_FILE_UPLOAD_LIST_POLL_MAX = 2
DEFAULT_FILE_UPLOAD_FALLBACK_DIRS_MAX = 5
DEFAULT_FILE_UPLOAD_USE_DOM_PARSER = True
DEFAULT_FILE_UPLOAD_SKIP_PAGE_DISCOVERY_WHEN_PATHS_FOUND = True
DEFAULT_FILE_UPLOAD_DISCOVERY_FETCH_CONCURRENCY = 4

_RUNTIME_CONFIG: "FuzzerRuntimeConfig | None" = None


def clamp_text(body: str, max_bytes: int) -> str:
    if not body or len(body) <= max_bytes:
        return body
    return body[:max_bytes]


def _parse_optional_bytes(raw: str) -> int | None:
    text = (raw or "").strip().lower()
    if not text or text in {"0", "none", "unlimited", "off", "false", "no"}:
        return None
    return int(text)


def _parse_bool(raw: str, default: bool) -> bool:
    text = (raw or "").strip().lower()
    if not text:
        return default
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _parse_positive_int(raw: str | None, default: int) -> int:
    text = (raw or "").strip()
    if not text:
        return default
    return max(1, int(text))


@dataclass(frozen=True, slots=True)
class StoredXSSConfig:
    """
    Stored XSS memory/verify limits.
    Env: FUZZER_STORED_XSS_ANALYZE_BODY_BYTES, VERIFY_BODY_BYTES,
         DOM_WINDOW_BYTES, BASELINE_BODY_BYTES, ABSOLUTE_MAX_BYTES,
         VERIFY_CONCURRENCY, VERIFY_MAX_URLS, LIST_POLL_MAX, LOCK_MAP_SIZE,
         MAX_CONCURRENT, MAX_WORKERS, VERIFY_DETAIL_MAX, PROGRESS_BLOCKS_MAX,
         WAF_COMPARE_BYTES, USE_DOM_PARSER.
    """

    analyze_body_bytes: int = DEFAULT_STORED_XSS_ANALYZE_BODY_BYTES
    verify_body_bytes: int = DEFAULT_STORED_XSS_VERIFY_BODY_BYTES
    dom_window_bytes: int = DEFAULT_STORED_XSS_DOM_WINDOW_BYTES
    baseline_body_bytes: int = DEFAULT_STORED_XSS_BASELINE_BODY_BYTES
    absolute_max_bytes: int = DEFAULT_STORED_XSS_ABSOLUTE_MAX_BYTES
    verify_concurrency: int = DEFAULT_STORED_XSS_VERIFY_CONCURRENCY
    verify_max_urls: int = DEFAULT_STORED_XSS_VERIFY_MAX_URLS
    list_poll_max: int = DEFAULT_STORED_XSS_LIST_POLL_MAX
    lock_map_size: int = DEFAULT_STORED_XSS_LOCK_MAP_SIZE
    max_concurrent_requests: int = DEFAULT_STORED_XSS_MAX_CONCURRENT
    max_workers: int = DEFAULT_STORED_XSS_MAX_WORKERS
    verify_detail_max_items: int = DEFAULT_STORED_XSS_VERIFY_DETAIL_MAX
    progress_log_blocks_max: int = DEFAULT_STORED_XSS_PROGRESS_BLOCKS_MAX
    waf_compare_bytes: int = DEFAULT_STORED_XSS_WAF_COMPARE_BYTES
    use_dom_parser: bool = DEFAULT_STORED_XSS_USE_DOM_PARSER

    @classmethod
    def from_env(cls) -> StoredXSSConfig:
        return cls(
            analyze_body_bytes=_parse_positive_int(
                os.getenv("FUZZER_STORED_XSS_ANALYZE_BODY_BYTES"),
                DEFAULT_STORED_XSS_ANALYZE_BODY_BYTES,
            ),
            verify_body_bytes=_parse_positive_int(
                os.getenv("FUZZER_STORED_XSS_VERIFY_BODY_BYTES"),
                DEFAULT_STORED_XSS_VERIFY_BODY_BYTES,
            ),
            dom_window_bytes=_parse_positive_int(
                os.getenv("FUZZER_STORED_XSS_DOM_WINDOW_BYTES"),
                DEFAULT_STORED_XSS_DOM_WINDOW_BYTES,
            ),
            baseline_body_bytes=_parse_positive_int(
                os.getenv("FUZZER_STORED_XSS_BASELINE_BODY_BYTES"),
                DEFAULT_STORED_XSS_BASELINE_BODY_BYTES,
            ),
            absolute_max_bytes=_parse_positive_int(
                os.getenv("FUZZER_STORED_XSS_ABSOLUTE_MAX_BYTES"),
                DEFAULT_STORED_XSS_ABSOLUTE_MAX_BYTES,
            ),
            verify_concurrency=_parse_positive_int(
                os.getenv("FUZZER_STORED_XSS_VERIFY_CONCURRENCY"),
                DEFAULT_STORED_XSS_VERIFY_CONCURRENCY,
            ),
            verify_max_urls=_parse_positive_int(
                os.getenv("FUZZER_STORED_XSS_VERIFY_MAX_URLS"),
                DEFAULT_STORED_XSS_VERIFY_MAX_URLS,
            ),
            list_poll_max=_parse_positive_int(
                os.getenv("FUZZER_STORED_XSS_LIST_POLL_MAX"),
                DEFAULT_STORED_XSS_LIST_POLL_MAX,
            ),
            lock_map_size=_parse_positive_int(
                os.getenv("FUZZER_STORED_XSS_LOCK_MAP_SIZE"),
                DEFAULT_STORED_XSS_LOCK_MAP_SIZE,
            ),
            max_concurrent_requests=_parse_positive_int(
                os.getenv("FUZZER_STORED_XSS_MAX_CONCURRENT"),
                DEFAULT_STORED_XSS_MAX_CONCURRENT,
            ),
            max_workers=_parse_positive_int(
                os.getenv("FUZZER_STORED_XSS_MAX_WORKERS"),
                DEFAULT_STORED_XSS_MAX_WORKERS,
            ),
            verify_detail_max_items=_parse_positive_int(
                os.getenv("FUZZER_STORED_XSS_VERIFY_DETAIL_MAX"),
                DEFAULT_STORED_XSS_VERIFY_DETAIL_MAX,
            ),
            progress_log_blocks_max=_parse_positive_int(
                os.getenv("FUZZER_STORED_XSS_PROGRESS_BLOCKS_MAX"),
                DEFAULT_STORED_XSS_PROGRESS_BLOCKS_MAX,
            ),
            waf_compare_bytes=_parse_positive_int(
                os.getenv("FUZZER_STORED_XSS_WAF_COMPARE_BYTES"),
                DEFAULT_STORED_XSS_WAF_COMPARE_BYTES,
            ),
            use_dom_parser=_parse_bool(
                os.getenv("FUZZER_STORED_XSS_USE_DOM_PARSER", ""),
                DEFAULT_STORED_XSS_USE_DOM_PARSER,
            ),
        )

    def _clamp(self, value: int, global_max: int | None) -> int:
        limit = min(value, self.absolute_max_bytes)
        if global_max is not None:
            limit = min(limit, global_max)
        return max(1, limit)

    def resolved_analyze_bytes(self, global_max: int | None) -> int:
        return self._clamp(self.analyze_body_bytes, global_max)

    def resolved_verify_bytes(self, global_max: int | None) -> int:
        return self._clamp(self.verify_body_bytes, global_max)

    def resolved_baseline_bytes(self, global_max: int | None) -> int:
        return self._clamp(self.baseline_body_bytes, global_max)


@dataclass(frozen=True, slots=True)
class LFIConfig:
    """LFI analyze limits. Env: FUZZER_LFI_ANALYZE_BODY_BYTES, ABSOLUTE_MAX_BYTES."""

    analyze_body_bytes: int = DEFAULT_LFI_ANALYZE_BODY_BYTES
    absolute_max_bytes: int = DEFAULT_LFI_ABSOLUTE_MAX_BYTES

    @classmethod
    def from_env(cls) -> LFIConfig:
        return cls(
            analyze_body_bytes=_parse_positive_int(
                os.getenv("FUZZER_LFI_ANALYZE_BODY_BYTES"),
                DEFAULT_LFI_ANALYZE_BODY_BYTES,
            ),
            absolute_max_bytes=_parse_positive_int(
                os.getenv("FUZZER_LFI_ABSOLUTE_MAX_BYTES"),
                DEFAULT_LFI_ABSOLUTE_MAX_BYTES,
            ),
        )

    def _clamp(self, value: int, global_max: int | None) -> int:
        limit = min(value, self.absolute_max_bytes)
        if global_max is not None:
            limit = min(limit, global_max)
        return max(1, limit)

    def resolved_analyze_bytes(self, global_max: int | None) -> int:
        return self._clamp(self.analyze_body_bytes, global_max)


@dataclass(frozen=True, slots=True)
class FileUploadConfig:
    """
    File upload analyze/verify/discovery limits.
    Env: FUZZER_FILE_UPLOAD_ANALYZE_BODY_BYTES, VERIFY_BODY_BYTES, DISCOVERY_BODY_BYTES, ...
    """

    analyze_body_bytes: int = DEFAULT_FILE_UPLOAD_ANALYZE_BODY_BYTES
    verify_body_bytes: int = DEFAULT_FILE_UPLOAD_VERIFY_BODY_BYTES
    discovery_body_bytes: int = DEFAULT_FILE_UPLOAD_DISCOVERY_BODY_BYTES
    absolute_max_bytes: int = DEFAULT_FILE_UPLOAD_ABSOLUTE_MAX_BYTES
    verify_max_urls: int = DEFAULT_FILE_UPLOAD_VERIFY_MAX_URLS
    verify_concurrency: int = DEFAULT_FILE_UPLOAD_VERIFY_CONCURRENCY
    verify_fetch_concurrency: int = DEFAULT_FILE_UPLOAD_VERIFY_FETCH_CONCURRENCY
    max_page_probes: int = DEFAULT_FILE_UPLOAD_MAX_PAGE_PROBES
    max_post_details: int = DEFAULT_FILE_UPLOAD_MAX_POST_DETAILS
    list_poll_max: int = DEFAULT_FILE_UPLOAD_LIST_POLL_MAX
    fallback_dirs_max: int = DEFAULT_FILE_UPLOAD_FALLBACK_DIRS_MAX
    use_dom_parser: bool = DEFAULT_FILE_UPLOAD_USE_DOM_PARSER
    skip_page_discovery_when_paths_found: bool = (
        DEFAULT_FILE_UPLOAD_SKIP_PAGE_DISCOVERY_WHEN_PATHS_FOUND
    )
    discovery_fetch_concurrency: int = DEFAULT_FILE_UPLOAD_DISCOVERY_FETCH_CONCURRENCY

    @classmethod
    def from_env(cls) -> FileUploadConfig:
        return cls(
            analyze_body_bytes=_parse_positive_int(
                os.getenv("FUZZER_FILE_UPLOAD_ANALYZE_BODY_BYTES"),
                DEFAULT_FILE_UPLOAD_ANALYZE_BODY_BYTES,
            ),
            verify_body_bytes=_parse_positive_int(
                os.getenv("FUZZER_FILE_UPLOAD_VERIFY_BODY_BYTES"),
                DEFAULT_FILE_UPLOAD_VERIFY_BODY_BYTES,
            ),
            discovery_body_bytes=_parse_positive_int(
                os.getenv("FUZZER_FILE_UPLOAD_DISCOVERY_BODY_BYTES"),
                DEFAULT_FILE_UPLOAD_DISCOVERY_BODY_BYTES,
            ),
            absolute_max_bytes=_parse_positive_int(
                os.getenv("FUZZER_FILE_UPLOAD_ABSOLUTE_MAX_BYTES"),
                DEFAULT_FILE_UPLOAD_ABSOLUTE_MAX_BYTES,
            ),
            verify_max_urls=_parse_positive_int(
                os.getenv("FUZZER_FILE_UPLOAD_VERIFY_MAX_URLS"),
                DEFAULT_FILE_UPLOAD_VERIFY_MAX_URLS,
            ),
            verify_concurrency=_parse_positive_int(
                os.getenv("FUZZER_FILE_UPLOAD_VERIFY_CONCURRENCY"),
                DEFAULT_FILE_UPLOAD_VERIFY_CONCURRENCY,
            ),
            verify_fetch_concurrency=_parse_positive_int(
                os.getenv("FUZZER_FILE_UPLOAD_VERIFY_FETCH_CONCURRENCY"),
                DEFAULT_FILE_UPLOAD_VERIFY_FETCH_CONCURRENCY,
            ),
            max_page_probes=_parse_positive_int(
                os.getenv("FUZZER_FILE_UPLOAD_MAX_PAGE_PROBES"),
                DEFAULT_FILE_UPLOAD_MAX_PAGE_PROBES,
            ),
            max_post_details=_parse_positive_int(
                os.getenv("FUZZER_FILE_UPLOAD_MAX_POST_DETAILS"),
                DEFAULT_FILE_UPLOAD_MAX_POST_DETAILS,
            ),
            list_poll_max=_parse_positive_int(
                os.getenv("FUZZER_FILE_UPLOAD_LIST_POLL_MAX"),
                DEFAULT_FILE_UPLOAD_LIST_POLL_MAX,
            ),
            fallback_dirs_max=_parse_positive_int(
                os.getenv("FUZZER_FILE_UPLOAD_FALLBACK_DIRS_MAX"),
                DEFAULT_FILE_UPLOAD_FALLBACK_DIRS_MAX,
            ),
            use_dom_parser=_parse_bool(
                os.getenv("FUZZER_FILE_UPLOAD_USE_DOM_PARSER", ""),
                DEFAULT_FILE_UPLOAD_USE_DOM_PARSER,
            ),
            skip_page_discovery_when_paths_found=_parse_bool(
                os.getenv("FUZZER_FILE_UPLOAD_SKIP_PAGE_DISCOVERY_WHEN_PATHS_FOUND", ""),
                DEFAULT_FILE_UPLOAD_SKIP_PAGE_DISCOVERY_WHEN_PATHS_FOUND,
            ),
            discovery_fetch_concurrency=_parse_positive_int(
                os.getenv("FUZZER_FILE_UPLOAD_DISCOVERY_FETCH_CONCURRENCY"),
                DEFAULT_FILE_UPLOAD_DISCOVERY_FETCH_CONCURRENCY,
            ),
        )

    def _clamp(self, value: int, global_max: int | None) -> int:
        limit = min(value, self.absolute_max_bytes)
        if global_max is not None:
            limit = min(limit, global_max)
        return max(1, limit)

    def resolved_analyze_bytes(self, global_max: int | None) -> int:
        return self._clamp(self.analyze_body_bytes, global_max)

    def resolved_verify_bytes(self, global_max: int | None) -> int:
        return self._clamp(self.verify_body_bytes, global_max)

    def resolved_discovery_bytes(self, global_max: int | None) -> int:
        return self._clamp(self.discovery_body_bytes, global_max)


@dataclass(frozen=True, slots=True)
class FuzzerRuntimeConfig:
    """
    Cross-cutting fuzzer runtime limits.
    All fields can be overridden per engine instance or via environment variables.
    """

    max_response_body_bytes: int | None = DEFAULT_MAX_RESPONSE_BODY_BYTES
    cache_module_payloads: bool = DEFAULT_CACHE_MODULE_PAYLOADS
    stored_xss: StoredXSSConfig = field(default_factory=StoredXSSConfig)
    lfi: LFIConfig = field(default_factory=LFIConfig)
    file_upload: FileUploadConfig = field(default_factory=FileUploadConfig)

    @classmethod
    def from_env(cls, **overrides: Any) -> FuzzerRuntimeConfig:
        env_limit = os.getenv("FUZZER_MAX_RESPONSE_BODY_BYTES")
        if env_limit is None:
            max_body = DEFAULT_MAX_RESPONSE_BODY_BYTES
        else:
            max_body = _parse_optional_bytes(env_limit)

        base = cls(
            max_response_body_bytes=max_body,
            cache_module_payloads=_parse_bool(
                os.getenv("FUZZER_CACHE_MODULE_PAYLOADS", ""),
                DEFAULT_CACHE_MODULE_PAYLOADS,
            ),
            stored_xss=StoredXSSConfig.from_env(),
            lfi=LFIConfig.from_env(),
            file_upload=FileUploadConfig.from_env(),
        )
        if not overrides:
            return base
        return replace(base, **overrides)


def get_fuzzer_runtime_config() -> FuzzerRuntimeConfig:
    global _RUNTIME_CONFIG
    if _RUNTIME_CONFIG is None:
        _RUNTIME_CONFIG = FuzzerRuntimeConfig.from_env()
    return _RUNTIME_CONFIG


def configure_fuzzer_runtime(
    config: FuzzerRuntimeConfig | None = None,
    **overrides: Any,
) -> FuzzerRuntimeConfig:
    """Install the active runtime config (env defaults + optional overrides)."""
    global _RUNTIME_CONFIG
    if config is not None:
        _RUNTIME_CONFIG = config
    elif overrides:
        _RUNTIME_CONFIG = replace(get_fuzzer_runtime_config(), **overrides)
    else:
        _RUNTIME_CONFIG = FuzzerRuntimeConfig.from_env()
    return _RUNTIME_CONFIG


def reset_fuzzer_runtime_config() -> None:
    """Restore lazy env-based config (useful in tests and between pipeline modules)."""
    global _RUNTIME_CONFIG
    _RUNTIME_CONFIG = None


def _module_response_cap(cfg: FuzzerRuntimeConfig, module_type: str) -> int | None:
    resolvers = {
        "stored_xss": cfg.stored_xss.resolved_analyze_bytes,
        "lfi": cfg.lfi.resolved_analyze_bytes,
        "file_upload": cfg.file_upload.resolved_analyze_bytes,
    }
    resolver = resolvers.get(module_type)
    if resolver is None:
        return cfg.max_response_body_bytes
    return resolver(cfg.max_response_body_bytes)


def apply_module_runtime_policy(module_type: str) -> FuzzerRuntimeConfig:
    """
    Apply per-module response limits before a pipeline stage.
    Caps global FUZZER_MAX_RESPONSE_BODY_BYTES at module analyze limit so
    fuzz + baseline reads stay bounded without per-request hardcoding.
    """
    cfg = FuzzerRuntimeConfig.from_env()
    cap = _module_response_cap(cfg, module_type)
    if cap is not None and module_type in {"stored_xss", "lfi", "file_upload"}:
        cfg = replace(cfg, max_response_body_bytes=cap)
    configure_fuzzer_runtime(cfg)
    return cfg
