"""Skool session cookies: env (preferred), cookie file, optional Chrome DB.

Never log or return cookie/token values. Stdlib only.
Linux Chrome v10 uses the well-known peanuts key + AES-128-CBC.
macOS Keychain / Windows DPAPI / Chrome v11+ are not decrypted here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

COOKIE_NAMES = ("auth_token", "client_id", "aws-waf-token")
ENV_BY_COOKIE = {
    "auth_token": "SKOOL_AUTH_TOKEN",
    "client_id": "SKOOL_CLIENT_ID",
    "aws-waf-token": "SKOOL_AWS_WAF_TOKEN",
}
SECRET_ENV = tuple(ENV_BY_COOKIE[name] for name in COOKIE_NAMES)
PLACEHOLDER_RE = re.compile(r"^\$\{[A-Z0-9_]+\}$")
HOST_OK = {".skool.com", "skool.com", "www.skool.com", ".www.skool.com"}

# Chrome Linux OSCrypt (v10): PBKDF2-HMAC-SHA1("peanuts", "saltysalt", 1, 16)
_CHROME_SALT = b"saltysalt"
_CHROME_IV = b" " * 16
_CHROME_EPOCH_DELTA = 11644473600  # seconds: 1601-01-01 → 1970-01-01


class AuthError(Exception):
    """User-visible auth failure; message must never contain secrets."""


# --- env -----------------------------------------------------------------------

def env_value(name: str) -> str | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    value = raw.strip()
    if not value or PLACEHOLDER_RE.match(value):
        return None
    return value


def env_flag_truthy(name: str) -> bool:
    value = env_value(name)
    if value is None:
        return False
    return value.lower() in ("1", "true", "yes", "on", "chrome")


def chrome_mode_enabled() -> bool:
    mode = (env_value("SKOOL_AUTH_MODE") or "").lower()
    if mode == "chrome":
        return True
    return env_flag_truthy("SKOOL_USE_CHROME")


def env_cookies() -> dict[str, str]:
    found: dict[str, str] = {}
    for cookie_name, env_name in ENV_BY_COOKIE.items():
        value = env_value(env_name)
        if value:
            found[cookie_name] = value
    return found


# --- JWT (exp only; never return the token) ------------------------------------

def jwt_expiry(auth_token: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "jwt_parsable": False,
        "expired": None,
        "expires_at": None,
    }
    parts = auth_token.split(".")
    if len(parts) != 3:
        return result
    payload_b64 = parts[1]
    pad = "=" * ((4 - len(payload_b64) % 4) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
    except (ValueError, json.JSONDecodeError, OSError):
        return result
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        result["jwt_parsable"] = True
        return result
    result["jwt_parsable"] = True
    expires = datetime.fromtimestamp(exp, tz=timezone.utc)
    result["expires_at"] = expires.isoformat()
    result["expired"] = time.time() >= float(exp)
    return result

