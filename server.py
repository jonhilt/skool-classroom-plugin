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
