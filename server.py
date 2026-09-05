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
