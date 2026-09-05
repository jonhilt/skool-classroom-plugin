#!/usr/bin/env python3
"""Skool classroom MCP server (unofficial api2.skool.com + classroom page data).

Stdlib only. Stdio JSON-RPC. Never prints cookie or token values.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import auth as skool_auth

API_BASE = "https://api2.skool.com"
WEB_BASE = "https://www.skool.com"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
V2_PREFIX = "[v2]"
HEX_RE = re.compile(r"^[0-9a-fA-F]{16,32}$")
NEXT_DATA_RE = re.compile(
    r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
    re.DOTALL | re.IGNORECASE,
)
SECRET_ENV = skool_auth.SECRET_ENV
MAX_IMAGE_BYTES = 10 * 1024 * 1024

STATE_LABEL = {1: "Draft", 2: "Active"}
PRIVACY_LABEL = {
    0: "Open",
    1: "Level unlock",
    2: "Private",
    3: "Buy now",
    4: "Time unlock",
}

SERVER_NAME = "skool"
SERVER_VERSION = "0.1.1"


class ToolError(Exception):
    """User-visible tool failure (no secrets)."""


# ---------------------------------------------------------------------------
# Secrets — values leave this module only as a Cookie header or JWT payload
# ---------------------------------------------------------------------------

def _env_secret(name: str) -> str | None:
    return skool_auth.env_value(name)


def secret_present(name: str) -> bool:
    return skool_auth.env_value(name) is not None


def missing_secret_names() -> list[str]:
    return skool_auth.missing_cookie_env_names()


def require_secrets() -> None:
    try:
        skool_auth.require_session()
    except skool_auth.AuthError as exc:
        raise ToolError(str(exc)) from None


def cookie_header() -> str:
    try:
        return skool_auth.cookie_header()
    except skool_auth.AuthError as exc:
        raise ToolError(str(exc)) from None


def jwt_expiry(auth_token: str) -> dict[str, Any]:
    """Parse JWT exp without returning or logging the token."""
    return skool_auth.jwt_expiry(auth_token)


def redact_text(text: str, limit: int = 800) -> str:
    """Strip token-like strings before returning API error snippets."""
    if not text:
        return ""
    cleaned = re.sub(
        r"(auth_token|client_id|aws-waf-token|Bearer)\s*[=:]\s*[^;\s&]+",
        r"\1=<redacted>",
        text,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "<jwt>", cleaned)
    cleaned = re.sub(r"[A-Za-z0-9+/]{80,}={0,2}", "<blob>", cleaned)
    if len(cleaned) > limit:
        return cleaned[:limit] + "…"
    return cleaned


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _headers(accept: str, slug: str | None = None, json_body: bool = False) -> dict[str, str]:
    referer = f"{WEB_BASE}/{slug}/classroom" if slug else f"{WEB_BASE}/"
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": accept,
        "Cookie": cookie_header(),
        "Origin": WEB_BASE,
        "Referer": referer,
    }
    if json_body:
        headers["Content-Type"] = "application/json; charset=utf-8"
    return headers


def http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 45,
    attach_cookies: bool = True,
) -> tuple[int, dict[str, str], bytes]:
    hdrs = dict(headers or {})
    if attach_cookies and "Cookie" not in hdrs:
        hdrs.update(_headers("application/json, text/plain, */*"))
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as exc:
        err_body = b""
        try:
            err_body = exc.read()
        except OSError:
            pass
        snippet = redact_text(err_body.decode("utf-8", errors="replace"))
        raise ToolError(
            f"HTTP {exc.code} {method} {urllib.parse.urlparse(url).path or url}: {snippet or exc.reason}"
        ) from None
    except urllib.error.URLError as exc:
        raise ToolError(f"Network error contacting Skool: {exc.reason}") from None


def api_json(
    path: str,
    method: str = "GET",
    payload: Any = None,
    slug: str | None = None,
) -> Any:
    url = path if path.startswith("http") else f"{API_BASE}{path}"
    body = None
    headers = _headers("application/json, text/plain, */*", slug=slug, json_body=payload is not None)
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    status, _hdrs, raw = http_request(url, method=method, headers=headers, body=body)
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        raise ToolError(
            f"Non-JSON response from {urllib.parse.urlparse(url).path} (HTTP {status})"
        ) from None


def fetch_html(url: str, slug: str | None = None) -> str:
    headers = _headers("text/html,application/xhtml+xml;q=0.9,*/*;q=0.8", slug=slug)
    _status, _hdrs, raw = http_request(url, headers=headers)
    return raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------

def as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def unwrap_unit(node: Any) -> tuple[dict[str, Any], list[Any]]:
    if not isinstance(node, dict):
        return {}, []
    children = node.get("children") if isinstance(node.get("children"), list) else []
    inner = node.get("course")
    if isinstance(inner, dict):
        nested_children = inner.get("children") if isinstance(inner.get("children"), list) else None
        return inner, children if children else (nested_children or [])
    return node, children


def _meta(unit: dict[str, Any]) -> dict[str, Any]:
    return as_dict(unit.get("metadata"))


def _pick(unit: dict[str, Any], meta: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in unit and unit[key] not in (None, ""):
            return unit[key]
        if key in meta and meta[key] not in (None, ""):
            return meta[key]
    return None


def summarize_course(unit: dict[str, Any], children: list[Any] | None = None) -> dict[str, Any]:
    meta = _meta(unit)
    state = _pick(unit, meta, "state")
    privacy = _pick(unit, meta, "privacy")
    summary: dict[str, Any] = {
        "id": unit.get("id"),
        "name": unit.get("name"),
        "title": _pick(unit, meta, "title") or "",
        "state": state,
        "state_label": STATE_LABEL.get(state) if isinstance(state, int) else None,
        "privacy": privacy,
        "privacy_label": PRIVACY_LABEL.get(privacy) if isinstance(privacy, int) else None,
    }
    min_tier = _pick(unit, meta, "min_tier")
    if min_tier is not None:
        summary["min_tier"] = min_tier
    if children is not None:
        summary["children"] = [summarize_lesson(*unwrap_unit(child)) for child in children]
    return summary


def summarize_lesson(unit: dict[str, Any], children: list[Any] | None = None) -> dict[str, Any]:
    meta = _meta(unit)
    item: dict[str, Any] = {
        "id": unit.get("id"),
        "name": unit.get("name"),
        "title": _pick(unit, meta, "title") or "",
        "unit_type": unit.get("unit_type") or meta.get("unit_type"),
        "parent_id": unit.get("parent_id") or unit.get("parentId"),
    }
    desc = meta.get("desc") if "desc" in meta else unit.get("desc")
    if desc is not None:
        item["desc"] = desc
    if children:
        item["children"] = [summarize_lesson(*unwrap_unit(child)) for child in children]
    return item


def lesson_list_item(unit: dict[str, Any]) -> dict[str, Any]:
    item = summarize_lesson(unit)
    item.pop("desc", None)
    item.pop("children", None)
    return item


def walk_units(node: Any) -> list[dict[str, Any]]:
    unit, children = unwrap_unit(node)
    out: list[dict[str, Any]] = []
    if unit.get("id"):
        out.append(unit)
    for child in children:
        out.extend(walk_units(child))
    return out


def looks_like_course_unit(unit: dict[str, Any]) -> bool:
    ut = unit.get("unit_type")
    if ut == "course":
        return True
    if ut in ("module", "set"):
        return False
    meta = _meta(unit)
    parent = unit.get("parent_id") or unit.get("parentId")
    if parent:
        return False
    return bool(unit.get("id") and (meta.get("title") or unit.get("title")) and "privacy" in meta)


def collect_courses(obj: Any, found: list[dict[str, Any]], seen: set[str]) -> None:
    if isinstance(obj, dict):
        unit, _children = unwrap_unit(obj)
        uid = str(unit.get("id") or "")
        if uid and uid not in seen and looks_like_course_unit(unit):
            seen.add(uid)
            found.append(unit)
        for value in obj.values():
            collect_courses(value, found, seen)
    elif isinstance(obj, list):
        for item in obj:
            collect_courses(item, found, seen)


def parse_next_data(html: str) -> dict[str, Any]:
    match = NEXT_DATA_RE.search(html)
    if not match:
        raise ToolError("Classroom page did not contain __NEXT_DATA__; session may be expired.")
    try:
        data = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        raise ToolError("Classroom page __NEXT_DATA__ was not valid JSON.") from exc
    if not isinstance(data, dict):
        raise ToolError("Classroom page __NEXT_DATA__ had an unexpected shape.")
    return data


def extract_group_id(obj: Any) -> str | None:
    found: list[str] = []

    def walk(node: Any) -> None:
        if found:
            return
        if isinstance(node, dict):
            for key in ("group_id", "groupId"):
                value = node.get(key)
                if isinstance(value, str) and HEX_RE.match(value):
                    found.append(value)
                    return
            g = node.get("group") or node.get("currentGroup")
            if isinstance(g, dict) and isinstance(g.get("id"), str) and HEX_RE.match(g["id"]):
                found.append(g["id"])
                return
            for value in node.values():
                walk(value)
                if found:
                    return
        elif isinstance(node, list):
            for item in node:
                walk(item)
                if found:
                    return

    walk(obj)
    return found[0] if found else None


# ---------------------------------------------------------------------------
# TipTap / markdown
# ---------------------------------------------------------------------------

def parse_desc_nodes(desc: str | None) -> list[Any]:
    if not desc:
        return []
    text = str(desc)
    if text.startswith(V2_PREFIX):
        payload = text[len(V2_PREFIX) :].lstrip()
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return [{"type": "paragraph", "content": [{"type": "text", "text": text}]}]
        if isinstance(data, dict) and data.get("type") == "doc":
            content = data.get("content") or []
            return content if isinstance(content, list) else []
        if isinstance(data, list):
            return data
        return []
    return [{"type": "paragraph", "content": [{"type": "text", "text": text}]}]


def encode_desc(nodes: list[Any]) -> str:
    return V2_PREFIX + json.dumps(nodes, ensure_ascii=False, separators=(",", ":"))


def body_to_desc(body: str) -> str:
    text = body if isinstance(body, str) else ""
    stripped = text.strip()
    if stripped.startswith(V2_PREFIX):
        payload = stripped[len(V2_PREFIX) :].lstrip()
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ToolError("body starts with [v2] but the JSON is invalid.") from exc
        if isinstance(data, dict) and data.get("type") == "doc":
            nodes = data.get("content") if isinstance(data.get("content"), list) else []
        elif isinstance(data, list):
            nodes = data
        else:
            raise ToolError("[v2] payload must be a TipTap JSON array (or a doc with content[]).")
        return encode_desc(nodes)
    return encode_desc(markdown_to_tiptap(text))


def markdown_to_tiptap(md: str) -> list[dict[str, Any]]:
    lines = md.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    nodes: list[dict[str, Any]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip() == "":
            i += 1
            continue
        if line.startswith("```"):
            lang = line[3:].strip()
            chunk: list[str] = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                chunk.append(lines[i])
                i += 1
            if i < len(lines):
                i += 1
            code_node: dict[str, Any] = {
                "type": "codeBlock",
                "content": [{"type": "text", "text": "\n".join(chunk)}],
            }
            if lang:
                code_node["attrs"] = {"language": lang}
            nodes.append(code_node)
            continue
        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        if heading:
            level = min(max(len(heading.group(1)), 1), 3)
            if len(heading.group(1)) == 1:
                level = 2
            nodes.append(
                {
                    "type": "heading",
                    "attrs": {"level": level},
                    "content": parse_inlines(heading.group(2).strip()),
                }
            )
            i += 1
            continue
        if re.match(r"^>\s?", line):
            quote_lines: list[str] = []
            while i < len(lines) and re.match(r"^>\s?", lines[i]):
                quote_lines.append(re.sub(r"^>\s?", "", lines[i]))
                i += 1
            quote_text = " ".join(part.strip() for part in quote_lines if part.strip())
            nodes.append(
                {
                    "type": "blockquote",
                    "content": [
                        {"type": "paragraph", "content": parse_inlines(quote_text or quote_lines[0])}
                    ],
                }
            )
            continue
        if re.match(r"^\s*([-*]|\d+\.)\s+", line):
            ordered = bool(re.match(r"^\s*\d+\.\s+", line))
            items: list[dict[str, Any]] = []
            while i < len(lines) and re.match(r"^\s*([-*]|\d+\.)\s+", lines[i]):
                item_text = re.sub(r"^\s*([-*]|\d+\.)\s+", "", lines[i])
                items.append(
                    {
                        "type": "listItem",
                        "content": [{"type": "paragraph", "content": parse_inlines(item_text)}],
                    }
                )
                i += 1
            nodes.append(
                {
                    "type": "orderedList" if ordered else "bulletList",
                    "content": items,
                }
            )
            continue
        if re.match(r"^\s*\|.+\|\s*$", line):
            table_lines = []
            while i < len(lines) and re.match(r"^\s*\|.+\|\s*$", lines[i]):
                table_lines.append(lines[i].strip())
                i += 1
            nodes.append(
                {
                    "type": "codeBlock",
                    "content": [{"type": "text", "text": "\n".join(table_lines)}],
                }
            )
            continue
        para = [line]
        i += 1
        while i < len(lines) and lines[i].strip() and not _starts_block(lines[i]):
            para.append(lines[i])
            i += 1
        text = " ".join(p.strip() for p in para)
        img_only = re.fullmatch(r"!\[([^\]]*)\]\(([^)]+)\)", text.strip())
        if img_only:
            nodes.append({"type": "image", "attrs": {"src": img_only.group(2), "alt": img_only.group(1)}})
        else:
            nodes.append({"type": "paragraph", "content": parse_inlines(text)})
    return nodes or [{"type": "paragraph"}]


def _starts_block(line: str) -> bool:
    return bool(
        line.startswith("```")
        or re.match(r"^#{1,6}\s+", line)
        or re.match(r"^>\s?", line)
        or re.match(r"^\s*([-*]|\d+\.)\s+", line)
        or re.match(r"^\s*\|.+\|\s*$", line)
    )


def parse_inlines(text: str) -> list[dict[str, Any]]:
    pattern = re.compile(
        r"(!\[([^\]]*)\]\(([^)]+)\))"
        r"|(\[([^\]]+)\]\(([^)]+)\))"
        r"|(`([^`]+)`)"
        r"|(\*\*(.+?)\*\*)"
        r"|((?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*))"
        r"|(_(.+?)_)"
    )
    nodes: list[dict[str, Any]] = []
    pos = 0
    for match in pattern.finditer(text):
        if match.start() > pos:
            chunk = text[pos : match.start()]
            if chunk:
                nodes.append({"type": "text", "text": chunk})
        if match.group(1):
            nodes.append({"type": "image", "attrs": {"src": match.group(3), "alt": match.group(2)}})
        elif match.group(4):
            nodes.append(
                {
                    "type": "text",
                    "text": match.group(5),
                    "marks": [{"type": "link", "attrs": {"href": match.group(6)}}],
                }
            )
        elif match.group(7):
            nodes.append({"type": "text", "text": match.group(8), "marks": [{"type": "code"}]})
        elif match.group(9):
            nodes.append({"type": "text", "text": match.group(10), "marks": [{"type": "bold"}]})
        elif match.group(11):
            nodes.append({"type": "text", "text": match.group(12), "marks": [{"type": "italic"}]})
        elif match.group(13):
            nodes.append({"type": "text", "text": match.group(14), "marks": [{"type": "italic"}]})
        pos = match.end()
    if pos < len(text):
        nodes.append({"type": "text", "text": text[pos:]})
    return nodes or [{"type": "text", "text": ""}]


def tiptap_to_markdown(nodes: list[Any]) -> str:
    parts: list[str] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        rendered = _render_node(node)
        if rendered:
            parts.append(rendered)
    return "\n\n".join(parts).strip() + ("\n" if parts else "")


def _render_inlines(content: Any) -> str:
    if not isinstance(content, list):
        return ""
    out: list[str] = []
    for node in content:
        if not isinstance(node, dict):
            continue
        ntype = node.get("type")
        if ntype == "text":
            text = str(node.get("text") or "")
            for mark in node.get("marks") or []:
                if not isinstance(mark, dict):
                    continue
                mtype = mark.get("type")
                if mtype == "bold":
                    text = f"**{text}**"
                elif mtype == "italic":
                    text = f"*{text}*"
                elif mtype == "code":
                    text = f"`{text}`"
                elif mtype == "link":
                    href = as_dict(mark.get("attrs")).get("href") or ""
                    text = f"[{text}]({href})"
            out.append(text)
        elif ntype == "hardBreak":
            out.append("\n")
        elif ntype == "image":
            attrs = as_dict(node.get("attrs"))
            out.append(f"![{attrs.get('alt') or ''}]({attrs.get('src') or ''})")
        elif node.get("content"):
            out.append(_render_inlines(node.get("content")))
    return "".join(out)


def _render_node(node: dict[str, Any]) -> str:
    ntype = node.get("type")
    content = node.get("content")
    attrs = as_dict(node.get("attrs"))
    if ntype == "heading":
        level = int(attrs.get("level") or 2)
        return f"{'#' * level} {_render_inlines(content)}".rstrip()
    if ntype == "paragraph":
        return _render_inlines(content)
    if ntype == "blockquote":
        inner = "\n\n".join(_render_node(child) for child in content or [] if isinstance(child, dict))
        return "\n".join(f"> {line}" if line else ">" for line in inner.splitlines()) or ">"
    if ntype in ("bulletList", "orderedList"):
        lines: list[str] = []
        for idx, item in enumerate(content or [], start=1):
            if not isinstance(item, dict):
                continue
            body = "\n".join(
                _render_node(child) for child in item.get("content") or [] if isinstance(child, dict)
            )
            prefix = f"{idx}. " if ntype == "orderedList" else "- "
            first, *rest = (body or "").splitlines() or [""]
            lines.append(prefix + first)
            lines.extend(f"  {r}" for r in rest)
        return "\n".join(lines)
    if ntype == "codeBlock":
        lang = attrs.get("language") or ""
        code = _render_inlines(content) if content else str(node.get("text") or "")
        return f"```{lang}\n{code}\n```"
    if ntype == "image":
        return f"![{attrs.get('alt') or ''}]({attrs.get('src') or ''})"
    if ntype == "horizontalRule":
        return "---"
    if content:
        return "\n\n".join(_render_node(child) for child in content if isinstance(child, dict))
    return _render_inlines(content)


# ---------------------------------------------------------------------------
# Domain operations
# ---------------------------------------------------------------------------

def resolve_slug(args: dict[str, Any]) -> str:
    slug = (args.get("community_slug") or _env_secret("SKOOL_COMMUNITY_SLUG") or "").strip()
    if not slug:
        raise ToolError(
            "community_slug is required (pass it on the tool call, or set SKOOL_COMMUNITY_SLUG)."
        )
    return slug


def get_course_payload(course_hex: str, slug: str | None = None) -> dict[str, Any]:
    data = api_json(f"/courses/{course_hex}", slug=slug)
    if not isinstance(data, dict):
        raise ToolError(f"GET /courses/{course_hex} returned an unexpected payload.")
    return data


def load_unit(unit_id: str, slug: str | None = None) -> tuple[dict[str, Any], list[Any], dict[str, Any]]:
    payload = get_course_payload(unit_id, slug=slug)
    unit, children = unwrap_unit(payload)
    if not unit.get("id"):
        unit, children = unwrap_unit(payload.get("course") or payload)
    if not unit.get("id"):
        raise ToolError(f"No course/module with id {unit_id}.")
    return unit, children, payload


def session_expired_hint(message: str) -> str:
    lowered = message.lower()
    if any(code in message for code in ("401", "403")) or "unauthor" in lowered:
        return (
            message
            + " Session looks expired. Export fresh auth_token, client_id, and aws-waf-token "
            "cookies and paste them under Plugins → Configure."
        )
    return message


def scrape_classroom_courses(slug: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    html = fetch_html(f"{WEB_BASE}/{slug}/classroom", slug=slug)
    next_data = parse_next_data(html)
    found: list[dict[str, Any]] = []
    collect_courses(next_data, found, set())
    return found, next_data


def list_courses_for_slug(slug: str) -> dict[str, Any]:
    api_candidates = (
        f"/groups/{urllib.parse.quote(slug)}",
        f"/courses?group={urllib.parse.quote(slug)}",
    )
    for path in api_candidates:
        try:
            data = api_json(path, slug=slug)
        except ToolError:
            continue
        found: list[dict[str, Any]] = []
        collect_courses(data, found, set())
        if found:
            return {
                "community_slug": slug,
                "source": f"api:{path.split('?')[0]}",
                "courses": [summarize_course(unit) for unit in found],
            }
    try:
        found, _next_data = scrape_classroom_courses(slug)
    except ToolError as exc:
        raise ToolError(session_expired_hint(str(exc))) from None
    return {
        "community_slug": slug,
        "source": "classroom_page",
        "courses": [summarize_course(unit) for unit in found],
    }


def resolve_course_id(identifier: str, slug: str | None) -> str:
    ident = identifier.strip()
    if HEX_RE.match(ident):
        return ident
    if not slug:
        raise ToolError("Numeric course name requires community_slug (or SKOOL_COMMUNITY_SLUG).")
    listing = list_courses_for_slug(slug)
    matches = [
        c
        for c in listing["courses"]
        if str(c.get("name")) == ident or str(c.get("title") or "").lower() == ident.lower()
    ]
    if not matches:
        raise ToolError(f"No course matching name/title {ident!r} in community {slug}.")
    if len(matches) > 1:
        raise ToolError(
            "Multiple courses matched "
            f"{ident!r}; pass the hex id instead: "
            + ", ".join(f"{c.get('title')} ({c.get('id')})" for c in matches)
        )
    cid = matches[0].get("id")
    if not isinstance(cid, str):
        raise ToolError("Matched course is missing an id.")
    return cid


def filter_lessons(units: list[dict[str, Any]], query: str | None) -> list[dict[str, Any]]:
    items = [lesson_list_item(u) for u in units if u.get("unit_type") in ("module", "set") or not u.get("unit_type")]
    if not query:
        return items
    q = query.lower()
    return [
        item
        for item in items
        if q in str(item.get("id") or "").lower()
        or q in str(item.get("name") or "").lower()
        or q in str(item.get("title") or "").lower()
    ]


def put_module(module_id: str, title: str, desc: str, slug: str | None) -> Any:
    if title is None or title == "":
        raise ToolError("Refusing module PUT without title (omitting title blanks it).")
    body = {"title": title, "desc": desc}
    extra = set(body) - {"title", "desc"}
    if extra:
        raise ToolError("Internal error: module PUT must send {title, desc} only.")
    return api_json(f"/courses/{module_id}", method="PUT", payload=body, slug=slug)


def detect_image_type(data: bytes, filename: str | None, content_type: str | None) -> tuple[str, str]:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", "jpg"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "image/gif", "gif"
    if data[0:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp", "webp"
    if content_type:
        ext = {
            "image/jpeg": "jpg",
            "image/png": "png",
            "image/gif": "gif",
            "image/webp": "webp",
        }.get(content_type, "bin")
        return content_type, ext
    if filename and "." in filename:
        ext = filename.rsplit(".", 1)[-1].lower()
        mime = {
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "png": "image/png",
            "gif": "image/gif",
            "webp": "image/webp",
        }.get(ext)
        if mime:
            return mime, ext if ext != "jpeg" else "jpg"
    return "image/jpeg", "jpg"


def load_image_bytes(args: dict[str, Any]) -> tuple[bytes, str]:
    sources = [k for k in ("image_path", "image_url", "image_base64") if args.get(k)]
    if len(sources) != 1:
        raise ToolError("Provide exactly one of image_path, image_url, or image_base64.")
    if args.get("image_path"):
        path = str(args["image_path"])
        if os.path.isabs(path):
            raise ToolError("image_path must be a relative path.")
        normalized = os.path.normpath(path)
        if normalized.startswith(".."):
            raise ToolError("image_path must stay within the working directory.")
        try:
            with open(normalized, "rb") as handle:
                data = handle.read()
        except OSError as exc:
            raise ToolError(f"Could not read image_path: {exc.strerror}") from None
        return data, os.path.basename(normalized)
    if args.get("image_url"):
        url = str(args["image_url"])
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ToolError("image_url must be http(s).")
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = resp.read(MAX_IMAGE_BYTES + 1)
        except urllib.error.URLError as exc:
            raise ToolError(f"Could not fetch image_url: {exc.reason}") from None
        return data, os.path.basename(parsed.path) or "image.jpg"
    raw = str(args["image_base64"])
    if "," in raw and raw.strip().startswith("data:"):
        raw = raw.split(",", 1)[1]
    try:
        data = base64.b64decode(raw, validate=False)
    except (ValueError, OSError) as exc:
        raise ToolError(f"image_base64 is not valid base64: {exc}") from None
    return data, str(args.get("filename") or "image.jpg")


def _file_field(obj: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if obj.get(key):
            return obj[key]
    return None


def upload_public_image(
    data: bytes,
    filename: str,
    owner_id: str,
    content_type_hint: str | None,
    slug: str | None,
) -> dict[str, Any]:
    if len(data) > MAX_IMAGE_BYTES:
        raise ToolError(f"Image is larger than {MAX_IMAGE_BYTES} bytes.")
    if not data:
        raise ToolError("Image is empty.")
    content_type, ext = detect_image_type(data, filename, content_type_hint)
    safe_name = filename if "." in filename else f"{filename}.{ext}"
    register = api_json(
        "/files",
        method="POST",
        payload={
            "filename": safe_name,
            "content_type": content_type,
            "content_length": len(data),
            "owner_id": owner_id,
            "privacy": 0,
        },
        slug=slug,
    )
    file_obj = register.get("file") if isinstance(register, dict) else None
    if not isinstance(file_obj, dict):
        file_obj = register if isinstance(register, dict) else {}
    write_url = _file_field(file_obj, "write_url", "upload_url", "put_url", "signed_url", "url")
    read_url = _file_field(file_obj, "read_url", "url", "public_url")
    file_id = _file_field(file_obj, "id", "file_id")
    if isinstance(write_url, dict):
        write_url = write_url.get("url") or write_url.get("href")
    if not write_url:
        raise ToolError(
            "POST /files did not return a presigned write URL "
            "(response omitted read/write URLs; privacy may be wrong)."
        )
    put_headers = {"Content-Type": content_type, "x-amz-acl": "public-read"}
    try:
        http_request(
            str(write_url),
            method="PUT",
            headers=put_headers,
            body=data,
            attach_cookies=False,
        )
    except ToolError:
        http_request(
            str(write_url),
            method="PUT",
            headers={"Content-Type": content_type},
            body=data,
            attach_cookies=False,
        )
    if not read_url:
        raise ToolError("Upload succeeded but no public read_url was returned; image would not display.")
    return {
        "file_id": file_id,
        "read_url": read_url,
        "content_type": content_type,
        "filename": safe_name,
    }


def owner_id_for_unit(unit: dict[str, Any], slug: str | None) -> str:
    gid = unit.get("group_id") or unit.get("groupId") or _meta(unit).get("group_id")
    if isinstance(gid, str) and HEX_RE.match(gid):
        return gid
    if slug:
        try:
            group = api_json(f"/groups/{urllib.parse.quote(slug)}", slug=slug)
            extracted = extract_group_id(group)
            if extracted:
                return extracted
        except ToolError:
            pass
        _courses, next_data = scrape_classroom_courses(slug)
        extracted = extract_group_id(next_data)
        if extracted:
            return extracted
    raise ToolError("Could not determine group owner_id needed for POST /files.")


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

def tool_auth_status(_args: dict[str, Any]) -> dict[str, Any]:
    return skool_auth.auth_status_payload()


def tool_courses(args: dict[str, Any]) -> dict[str, Any]:
    require_secrets()
    slug = resolve_slug(args)
    try:
        return list_courses_for_slug(slug)
    except ToolError as exc:
        raise ToolError(session_expired_hint(str(exc))) from None


def tool_course_get(args: dict[str, Any]) -> dict[str, Any]:
    require_secrets()
    identifier = str(args.get("course_id") or args.get("id") or "").strip()
    if not identifier:
        raise ToolError("course_id is required (hex id, or numeric web name with community_slug).")
    slug = None
    try:
        slug = resolve_slug(args)
    except ToolError:
        slug = (args.get("community_slug") or "").strip() or None
    course_id = resolve_course_id(identifier, slug)
    unit, children, _payload = load_unit(course_id, slug=slug)
    if unit.get("unit_type") == "module":
        return {"course": summarize_lesson(unit, children), "note": "This id is a lesson/module, not a course root."}
    return {"course": summarize_course(unit, children)}


def tool_lessons(args: dict[str, Any]) -> dict[str, Any]:
    require_secrets()
    identifier = str(args.get("course_id") or args.get("id") or "").strip()
    if not identifier:
        raise ToolError("course_id is required.")
    slug = None
    try:
        slug = resolve_slug(args)
    except ToolError:
        slug = (args.get("community_slug") or "").strip() or None
    course_id = resolve_course_id(identifier, slug)
    unit, children, _payload = load_unit(course_id, slug=slug)
    if unit.get("unit_type") == "module":
        raise ToolError("course_id points at a lesson/module. Pass the course root hex id.")
    units = walk_units({"course": unit, "children": children})
    query = args.get("query") or args.get("filter")
    query_s = str(query) if query else None
    return {
        "course": summarize_course(unit),
        "lessons": filter_lessons(units, query_s),
    }


def tool_lesson_get(args: dict[str, Any]) -> dict[str, Any]:
    require_secrets()
    lesson_id = str(args.get("lesson_id") or args.get("id") or "").strip()
    if not lesson_id:
        raise ToolError("lesson_id is required.")
    slug = (args.get("community_slug") or "").strip() or None
    if not slug:
        try:
            slug = resolve_slug(args)
        except ToolError:
            slug = None
    unit, children, _payload = load_unit(lesson_id, slug=slug)
    ut = unit.get("unit_type")
    if ut == "course":
        raise ToolError(
            "This id is a course root. Use skool_course_get / skool_lessons. "
            "Never treat the course root as a lesson body."
        )
    fmt = str(args.get("format") or "markdown").lower()
    summary = summarize_lesson(unit, children)
    desc = summary.get("desc")
    nodes = parse_desc_nodes(desc if isinstance(desc, str) else None)
    out = {
        "lesson": {k: v for k, v in summary.items() if k != "desc"},
        "format": fmt,
    }
    if fmt == "raw":
        out["desc"] = desc
        out["nodes"] = nodes
    else:
        out["markdown"] = tiptap_to_markdown(nodes)
        if not (desc or "").startswith(V2_PREFIX) and desc:
            out["note"] = "desc was not [v2] TipTap; shown as plain text."
    return out


def _dry_run_flag(args: dict[str, Any]) -> bool:
    if "dry_run" not in args or args.get("dry_run") is None:
        return True
    value = args.get("dry_run")
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in ("false", "0", "no")
    return bool(value)


def tool_lesson_set(args: dict[str, Any]) -> dict[str, Any]:
    require_secrets()
    lesson_id = str(args.get("lesson_id") or args.get("id") or "").strip()
    body = args.get("body")
    if not lesson_id:
        raise ToolError("lesson_id is required.")
    if not isinstance(body, str):
        raise ToolError("body is required (markdown or [v2] TipTap text).")
    dry_run = _dry_run_flag(args)
    slug = (args.get("community_slug") or "").strip() or None
    if not slug:
        try:
            slug = resolve_slug(args)
        except ToolError:
            slug = None
    unit, _children, _payload = load_unit(lesson_id, slug=slug)
    ut = unit.get("unit_type")
    if ut == "course":
        raise ToolError(
            "Refusing to PUT a course root to edit a lesson. Pass the module/lesson hex id. "
            "Course PUTs that omit state or privacy can reset privacy or flip Draft→Active."
        )
    if ut == "set":
        raise ToolError("This id is a folder/set. Pass a module (lesson page) id.")
    meta = _meta(unit)
    current_title = _pick(unit, meta, "title") or ""
    title = args.get("title")
    title = current_title if title is None or title == "" else str(title)
    if not title:
        raise ToolError("Lesson has no title; pass title explicitly. Omitting title on set blanks it.")
    desc = body_to_desc(body)
    proposed = {"title": title, "desc": desc}
    result: dict[str, Any] = {
        "dry_run": dry_run,
        "lesson_id": unit.get("id") or lesson_id,
        "unit_type": ut,
        "put": {"path": f"/courses/{unit.get('id') or lesson_id}", "body_keys": ["title", "desc"]},
        "title": title,
        "markdown_preview": tiptap_to_markdown(parse_desc_nodes(desc)),
    }
    if dry_run:
        result["applied"] = False
        result["message"] = "dry_run=true (default). Re-call with dry_run=false to PUT {title, desc} only."
        return result
    put_module(str(unit.get("id") or lesson_id), title, desc, slug)
    result["applied"] = True
    result["message"] = "PUT {title, desc} sent."
    result["proposed"] = {k: proposed[k] for k in ("title",)}
    return result


def tool_lesson_attach_image(args: dict[str, Any]) -> dict[str, Any]:
    require_secrets()
    lesson_id = str(args.get("lesson_id") or args.get("id") or "").strip()
    if not lesson_id:
        raise ToolError("lesson_id is required.")
    dry_run = _dry_run_flag(args)
    slug = (args.get("community_slug") or "").strip() or None
    if not slug:
        try:
            slug = resolve_slug(args)
        except ToolError:
            slug = None
    unit, _children, _payload = load_unit(lesson_id, slug=slug)
    ut = unit.get("unit_type")
    if ut == "course":
        raise ToolError("Refusing to PUT a course root to attach an image. Pass the lesson/module hex id.")
    if ut == "set":
        raise ToolError("This id is a folder/set. Pass a module (lesson page) id.")
    meta = _meta(unit)
    title = str(args.get("title") or _pick(unit, meta, "title") or "")
    if not title:
        raise ToolError("Lesson has no title; pass title explicitly. Omitting title on set blanks it.")
    current_desc = meta.get("desc") if "desc" in meta else unit.get("desc")
    nodes = parse_desc_nodes(current_desc if isinstance(current_desc, str) else None)
    alt = str(args.get("alt") or "")
    result: dict[str, Any] = {
        "dry_run": dry_run,
        "lesson_id": unit.get("id") or lesson_id,
        "title": title,
        "put": {"path": f"/courses/{unit.get('id') or lesson_id}", "body_keys": ["title", "desc"]},
    }
    if dry_run:
        preview_nodes = list(nodes) + [
            {"type": "image", "attrs": {"src": "<would-upload>", "alt": alt}}
        ]
        result["applied"] = False
        result["upload"] = False
        result["markdown_preview"] = tiptap_to_markdown(preview_nodes)
        result["message"] = (
            "dry_run=true (default). No POST /files, no presigned PUT, and no module PUT were sent. "
            "Re-call with dry_run=false to upload and append the image."
        )
        return result
    data, filename = load_image_bytes(args)
    if args.get("filename"):
        filename = str(args["filename"])
    owner_id = owner_id_for_unit(unit, slug)
    uploaded = upload_public_image(
        data,
        filename,
        owner_id,
        args.get("content_type") if isinstance(args.get("content_type"), str) else None,
        slug,
    )
    nodes.append({"type": "image", "attrs": {"src": uploaded["read_url"], "alt": alt}})
    desc = encode_desc(nodes)
    put_module(str(unit.get("id") or lesson_id), title, desc, slug)
    result["applied"] = True
    result["upload"] = {"file_id": uploaded["file_id"], "read_url": uploaded["read_url"]}
    result["markdown_preview"] = tiptap_to_markdown(nodes)
    result["message"] = "Image uploaded and appended via module PUT {title, desc}."
    return result


TOOLS: dict[str, dict[str, Any]] = {
    "skool_auth_status": {
        "handler": tool_auth_status,
        "description": (
            "Report auth source (env | chrome | cookie_file | missing), which of the three "
            "cookies are present (booleans only), and JWT/cookie expiry if known. Never prints token values. "
            "Prefers env vars; optional SKOOL_COOKIE_FILE or SKOOL_AUTH_MODE=chrome (Linux v10)."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    "skool_courses": {
        "handler": tool_courses,
        "description": (
            "List classroom courses for a community slug. Prefers api2.skool.com when it returns courses; "
            "otherwise reads __NEXT_DATA__ from /{slug}/classroom. Unofficial API; session cookies required."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "community_slug": {
                    "type": "string",
                    "description": "Community slug (falls back to SKOOL_COMMUNITY_SLUG).",
                }
            },
            "additionalProperties": False,
        },
    },
    "skool_lessons": {
        "handler": tool_lessons,
        "description": (
            "List lessons/modules for a course via GET /courses/{courseHex}. "
            "Optional query matches id, name (numeric web id), or title substring. Does not return lesson bodies."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "course_id": {
                    "type": "string",
                    "description": "Course hex id, or numeric web name if community_slug is set.",
                },
                "query": {
                    "type": "string",
                    "description": "Optional substring filter on id, name, or title.",
                },
                "community_slug": {"type": "string"},
            },
            "required": ["course_id"],
            "additionalProperties": False,
        },
    },
    "skool_lesson_get": {
        "handler": tool_lesson_get,
        "description": (
            "Get one lesson/module body. format=markdown (default) or raw ([v2] TipTap). "
            "Never invent lesson text — returns stored desc only. Refuses course-root ids."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "lesson_id": {"type": "string", "description": "Module/lesson hex id."},
                "format": {
                    "type": "string",
                    "enum": ["markdown", "raw"],
                    "description": "markdown (default) or raw [v2] TipTap.",
                },
                "community_slug": {"type": "string"},
            },
            "required": ["lesson_id"],
            "additionalProperties": False,
        },
    },
    "skool_lesson_set": {
        "handler": tool_lesson_set,
        "description": (
            "Set a lesson body from markdown or [v2] TipTap. dry_run defaults to true — "
            "apply only when dry_run=false. PUTs {title, desc} only on the module; always echoes title. "
            "Refuses course-root ids (partial course PUT can reset privacy or flip Draft→Active)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "lesson_id": {"type": "string", "description": "Module/lesson hex id."},
                "body": {
                    "type": "string",
                    "description": "Markdown, or text starting with [v2] plus TipTap JSON.",
                },
                "title": {
                    "type": "string",
                    "description": "Optional title override. Defaults to the current title (required on PUT).",
                },
                "dry_run": {
                    "type": "boolean",
                    "default": True,
                    "description": "When true (default), preview only. Set false to PUT.",
                },
                "community_slug": {"type": "string"},
            },
            "required": ["lesson_id", "body"],
            "additionalProperties": False,
        },
    },
    "skool_lesson_attach_image": {
        "handler": tool_lesson_attach_image,
        "description": (
            "Upload an image (POST /files + presigned PUT) and append it to the lesson TipTap body. "
            "dry_run defaults to true. Apply with dry_run=false. Module PUT is {title, desc} only."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "lesson_id": {"type": "string"},
                "image_path": {
                    "type": "string",
                    "description": "Relative path to a local image file.",
                },
                "image_url": {"type": "string", "description": "http(s) URL to fetch and upload."},
                "image_base64": {"type": "string", "description": "Raw or data-URL base64 image bytes."},
                "filename": {"type": "string"},
                "content_type": {"type": "string"},
                "alt": {"type": "string"},
                "title": {"type": "string"},
                "dry_run": {"type": "boolean", "default": True},
                "community_slug": {"type": "string"},
            },
            "required": ["lesson_id"],
            "additionalProperties": False,
        },
    },
    "skool_course_get": {
        "handler": tool_course_get,
        "description": (
            "Get one course summary from GET /courses/{courseHex}: id, name (numeric web id), "
            "title, state (1=Draft, 2=Active), privacy, min_tier, children."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "course_id": {
                    "type": "string",
                    "description": "Course hex id, or numeric web name with community_slug.",
                },
                "community_slug": {"type": "string"},
            },
            "required": ["course_id"],
            "additionalProperties": False,
        },
    },
}


def tools_list() -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "description": spec["description"],
            "inputSchema": spec["inputSchema"],
        }
        for name, spec in TOOLS.items()
    ]


def dispatch_tool(name: str, arguments: Any) -> dict[str, Any]:
    spec = TOOLS.get(name)
    if spec is None:
        raise ToolError(f"Unknown tool: {name}")
    args = arguments if isinstance(arguments, dict) else {}
    result = spec["handler"](args)
    return result if isinstance(result, dict) else {"result": result}


# ---------------------------------------------------------------------------
# JSON-RPC stdio
# ---------------------------------------------------------------------------

def write_message(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def success(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def error_response(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": redact_text(message, 400)}}


def handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    req_id = message.get("id")
    params = message.get("params") if isinstance(message.get("params"), dict) else {}
    if method == "notifications/initialized" or method == "notifications/cancelled":
        return None
    if req_id is None:
        return None
    if method == "initialize":
        requested = params.get("protocolVersion") or "2024-11-05"
        protocol = requested if isinstance(requested, str) else "2024-11-05"
        return success(
            req_id,
            {
                "protocolVersion": protocol,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "instructions": (
                    "Unofficial Skool classroom API. Writes default to dry_run=true. "
                    "Never PUT a course root to edit a lesson. Refresh cookies under Plugins → Configure when the session expires."
                ),
            },
        )
    if method == "ping":
        return success(req_id, {})
    if method == "tools/list":
        return success(req_id, {"tools": tools_list()})
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments")
        try:
            if not isinstance(name, str):
                raise ToolError("tools/call requires a tool name.")
            result = dispatch_tool(name, arguments)
            return success(
                req_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, ensure_ascii=False, indent=2),
                        }
                    ]
                },
            )
        except ToolError as exc:
            return success(
                req_id,
                {
                    "content": [{"type": "text", "text": redact_text(str(exc), 1500)}],
                    "isError": True,
                },
            )
        except Exception:
            return success(
                req_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": "Internal error (details omitted so secrets cannot leak).",
                        }
                    ],
                    "isError": True,
                },
            )
    return error_response(req_id, -32601, f"Method not found: {method}")


def main() -> None:
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            break
        try:
            message = json.loads(line.decode("utf-8"))
        except json.JSONDecodeError:
            write_message(error_response(None, -32700, "Parse error"))
            continue
        if not isinstance(message, dict):
            write_message(error_response(None, -32600, "Invalid request"))
            continue
        reply = handle_request(message)
        if reply is not None:
            write_message(reply)


if __name__ == "__main__":
    main()
