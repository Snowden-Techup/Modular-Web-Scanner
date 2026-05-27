# crawler/dom_skeleton.py

"""
DOM structural skeleton extraction and hashing.

Combines:
  1) Action/capability fingerprint (forms, privileged links) — stable signal for
     permission-dependent UI such as board edit/delete/comment/edit.
  2) Normalized tag tree — layout similarity without visible text.

Comment/review list length is collapsed so dynamic repetition does not
drown out form/action differences between otherwise similar pages.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from urllib.parse import urlparse

from bs4 import BeautifulSoup, NavigableString, Tag

_SKIP_TAGS = frozenset({"script", "style", "noscript", "template", "svg"})
_STRUCTURAL_ATTRS = frozenset({"type", "method", "name", "role", "enctype"})
_LINK_ATTRS = frozenset({"action", "href", "formaction"})
_INTERESTING_PATH_RE = re.compile(
    r"(?:^|/)(?:edit|delete|comment|write|add|verify|upload|submit)(?:/|$)",
    re.IGNORECASE,
)
_MAX_TREE_DEPTH = 32
_MAX_IDENTICAL_SIBLINGS = 2


def _normalize_path_attr(value: str) -> str:
    """Collapse numeric segments: /board/view/12 -> /board/view/N."""
    if not value or value.startswith("#"):
        return ""
    raw = value.strip()
    parsed = urlparse(raw)
    path = parsed.path if parsed.scheme or parsed.netloc else raw.split("?")[0]
    path = re.sub(r"\d+", "N", path)
    query_keys = ()
    if parsed.query:
        query_keys = tuple(sorted(k.split("=")[0] for k in parsed.query.split("&") if k))
    if query_keys:
        return f"{path}?{','.join(query_keys)}"[:240]
    return path[:240]


def _attr_values(tag: Tag, key: str) -> str:
    val = tag.get(key)
    if val is None:
        return ""
    if isinstance(val, list):
        return " ".join(str(v) for v in val)
    return str(val)


def _default_form_action(page_url: str | None) -> str:
    if not page_url:
        return ""
    parsed = urlparse(page_url)
    if not parsed.path:
        return ""
    return _normalize_path_attr(
        parsed.path + (f"?{parsed.query}" if parsed.query else "")
    )


def capability_tokens(
    soup: BeautifulSoup, page_url: str | None = None
) -> frozenset[str]:
    """
    Form/button actions and privileged links for DOM hash and novelty detection.

    Intentionally excludes input field *names* (post_id, content, etc.).
    Forms without an action attribute use the current page path (HTML default).
    """
    tokens: set[str] = set()
    default_action = _default_form_action(page_url)

    for form in soup.find_all("form"):
        method = (_attr_values(form, "method") or "get").lower()
        action = _normalize_path_attr(_attr_values(form, "action"))
        if not action and default_action:
            action = default_action
        if action:
            tokens.add(f"form:{method}:{action}")

    for tag in soup.find_all("a", href=True):
        path = _normalize_path_attr(_attr_values(tag, "href"))
        path_only = path.split("?", 1)[0]
        if path_only and _INTERESTING_PATH_RE.search(path_only):
            tokens.add(f"a:{path}")

    for tag in soup.find_all("button"):
        path = _normalize_path_attr(_attr_values(tag, "formaction"))
        if path:
            method = (_attr_values(tag, "type") or "submit").lower()
            tokens.add(f"button:{method}:{path}")

    return frozenset(tokens)


def _collect_capabilities(soup: BeautifulSoup, page_url: str | None = None) -> str:
    tokens = capability_tokens(soup, page_url)
    if not tokens:
        return "cap:none"
    return "cap:" + ",".join(sorted(tokens))


def collect_form_actions(
    soup: BeautifulSoup, page_url: str | None = None
) -> frozenset[str]:
    """Alias for capability_tokens (forms + privileged links)."""
    return capability_tokens(soup, page_url)


def _tag_signature(tag: Tag) -> str:
    name = tag.name or "?"
    parts = [name]
    attrs = tag.attrs if isinstance(tag.attrs, dict) else {}
    for key in sorted(attrs.keys()):
        if key in ("class", "id", "style", "value", "src", "content"):
            continue
        val = tag.get(key)
        if val is None:
            continue
        if isinstance(val, list):
            val = " ".join(str(v) for v in val)
        else:
            val = str(val)
        if key in _STRUCTURAL_ATTRS:
            parts.append(f"{key}={val}")
        elif key in _LINK_ATTRS:
            norm = _normalize_path_attr(val)
            if norm:
                parts.append(f"{key}={norm}")
    return "(" + ",".join(parts[1:]) + ")" if len(parts) > 1 else name


def _collapse_repeated_siblings(signatures: list[str]) -> list[str]:
    """Avoid huge hashes from N comment blocks with the same subtree shape."""
    if not signatures:
        return signatures
    collapsed: list[str] = []
    counts = Counter(signatures)
    seen_repeat: set[str] = set()
    for sig in signatures:
        if counts[sig] > _MAX_IDENTICAL_SIBLINGS:
            if sig in seen_repeat:
                continue
            seen_repeat.add(sig)
            collapsed.append(f"{sig}*{_MAX_IDENTICAL_SIBLINGS}+")
        else:
            collapsed.append(sig)
    return collapsed


def build_skeleton_markup(soup: BeautifulSoup, root: Tag | None = None, depth: int = 0) -> str:
    """Depth-first tag skeleton without text nodes."""
    if depth > _MAX_TREE_DEPTH:
        return "…"
    if root is None:
        root = soup.body if soup.body else soup
    if not isinstance(root, Tag):
        return ""

    child_sigs: list[str] = []
    for child in root.children:
        if isinstance(child, NavigableString):
            continue
        if not isinstance(child, Tag):
            continue
        if child.name in _SKIP_TAGS:
            continue
        child_sigs.append(build_skeleton_markup(soup, child, depth + 1))

    child_sigs = [c for c in child_sigs if c]
    child_sigs = _collapse_repeated_siblings(child_sigs)
    inner = "".join(child_sigs)
    return f"{_tag_signature(root)}[{inner}]" if inner else _tag_signature(root)


def skeleton_hash(soup: BeautifulSoup, page_url: str | None = None) -> str:
    """
    16-char hex digest used for crawl structure quotas.

    Uses the capability fingerprint only (form actions + privileged links).
    The full tag tree is intentionally excluded here: it varies on almost every
    /board/view?id=N page and caused each ID to get a unique hash, burning
    max_urls on HTTP while barely increasing distinct attack surfaces.
    """
    capabilities = _collect_capabilities(soup, page_url)
    return hashlib.sha256(capabilities.encode("utf-8", errors="replace")).hexdigest()[:16]


def skeleton_hash_full(soup: BeautifulSoup) -> str:
    """Capability + tree (debug / future use)."""
    capabilities = _collect_capabilities(soup)
    tree = build_skeleton_markup(soup)
    payload = f"{capabilities}|tree:{tree}"
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]
