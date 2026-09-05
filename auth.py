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


# --- AES-128 (FIPS-197), used only for Chrome Linux v10 ------------------------

_SBOX = bytes(
    [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ]
)
_INV_SBOX = bytes({v: i for i, v in enumerate(_SBOX)}[n] for n in range(256))
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(a: int) -> int:
    a &= 0xFF
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def _gf_mul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _expand_key(key: bytes) -> list[list[int]]:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    w: list[int] = list(key)
    for i in range(4, 44):
        t0, t1, t2, t3 = w[-4], w[-3], w[-2], w[-1]
        if i % 4 == 0:
            t0, t1, t2, t3 = t1, t2, t3, t0
            t0, t1, t2, t3 = _SBOX[t0], _SBOX[t1], _SBOX[t2], _SBOX[t3]
            t0 ^= _RCON[i // 4 - 1]
        base = (i - 4) * 4
        w.extend(
            [
                w[base] ^ t0,
                w[base + 1] ^ t1,
                w[base + 2] ^ t2,
                w[base + 3] ^ t3,
            ]
        )
    rounds = []
    for r in range(11):
        chunk = w[r * 16 : (r + 1) * 16]
        rounds.append(chunk)
    return rounds


def _add_round_key(state: list[int], rk: list[int]) -> None:
    for i in range(16):
        state[i] ^= rk[i]


def _shift_rows(state: list[int], inverse: bool = False) -> None:
    def col_row(c: int, r: int) -> int:
        return c * 4 + r

    for r in range(1, 4):
        row = [state[col_row(c, r)] for c in range(4)]
        shift = -r if inverse else r
        row = row[shift:] + row[:shift]
        for c in range(4):
            state[col_row(c, r)] = row[c]


def _mix_columns(state: list[int], inverse: bool = False) -> None:
    coeffs = (0x0E, 0x0B, 0x0D, 0x09) if inverse else (0x02, 0x03, 0x01, 0x01)
    for c in range(4):
        i = c * 4
        a = state[i : i + 4]
        if inverse:
            state[i] = _gf_mul(a[0], coeffs[0]) ^ _gf_mul(a[1], coeffs[1]) ^ _gf_mul(a[2], coeffs[2]) ^ _gf_mul(a[3], coeffs[3])
            state[i + 1] = _gf_mul(a[0], coeffs[3]) ^ _gf_mul(a[1], coeffs[0]) ^ _gf_mul(a[2], coeffs[1]) ^ _gf_mul(a[3], coeffs[2])
            state[i + 2] = _gf_mul(a[0], coeffs[2]) ^ _gf_mul(a[1], coeffs[3]) ^ _gf_mul(a[2], coeffs[0]) ^ _gf_mul(a[3], coeffs[1])
            state[i + 3] = _gf_mul(a[0], coeffs[1]) ^ _gf_mul(a[1], coeffs[2]) ^ _gf_mul(a[2], coeffs[3]) ^ _gf_mul(a[3], coeffs[0])
        else:
            state[i] = _gf_mul(a[0], 2) ^ _gf_mul(a[1], 3) ^ a[2] ^ a[3]
            state[i + 1] = a[0] ^ _gf_mul(a[1], 2) ^ _gf_mul(a[2], 3) ^ a[3]
            state[i + 2] = a[0] ^ a[1] ^ _gf_mul(a[2], 2) ^ _gf_mul(a[3], 3)
            state[i + 3] = _gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf_mul(a[3], 2)


def aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    rk = _expand_key(key)
    state = list(block)
    _add_round_key(state, rk[0])
    for r in range(1, 10):
        for i in range(16):
            state[i] = _SBOX[state[i]]
        _shift_rows(state, False)
        _mix_columns(state, False)
        _add_round_key(state, rk[r])
    for i in range(16):
        state[i] = _SBOX[state[i]]
    _shift_rows(state, False)
    _add_round_key(state, rk[10])
    return bytes(state)


def aes128_decrypt_block(key: bytes, block: bytes) -> bytes:
    rk = _expand_key(key)
    state = list(block)
    _add_round_key(state, rk[10])
    _shift_rows(state, True)
    for i in range(16):
        state[i] = _INV_SBOX[state[i]]
    for r in range(9, 0, -1):
        _add_round_key(state, rk[r])
        _mix_columns(state, True)
        _shift_rows(state, True)
        for i in range(16):
            state[i] = _INV_SBOX[state[i]]
    _add_round_key(state, rk[0])
    return bytes(state)


def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    n = block - (len(data) % block)
    return data + bytes([n] * n)


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % 16 != 0:
        raise ValueError("bad padding")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n] * n):
        raise ValueError("bad padding")
    return data[:-n]


def aes128_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    data = pkcs7_pad(plaintext)
    prev = iv
    out = bytearray()
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i : i + 16], prev))
        enc = aes128_encrypt_block(key, block)
        out.extend(enc)
        prev = enc
    return bytes(out)


def aes128_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) < 16 or len(ciphertext) % 16 != 0:
        raise ValueError("bad ciphertext length")
    prev = iv
    out = bytearray()
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i : i + 16]
        dec = aes128_decrypt_block(key, block)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = block
    return pkcs7_unpad(bytes(out))


def chrome_v10_key(password: bytes = b"peanuts") -> bytes:
    return hashlib.pbkdf2_hmac("sha1", password, _CHROME_SALT, 1, dklen=16)


def chrome_v10_encrypt(plaintext: bytes, password: bytes = b"peanuts") -> bytes:
    return b"v10" + aes128_cbc_encrypt(chrome_v10_key(password), _CHROME_IV, plaintext)


def chrome_v10_decrypt(blob: bytes) -> str | None:
    if not blob.startswith(b"v10") or len(blob) < 19:
        return None
    ct = blob[3:]
    for password in (b"peanuts", b""):
        try:
            raw = aes128_cbc_decrypt(chrome_v10_key(password), _CHROME_IV, ct)
        except ValueError:
            continue
        text = _printable_utf8(raw)
        if text is not None:
            return text
    return None


def _printable_utf8(raw: bytes) -> str | None:
    if not raw:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(ch) < 32 and ch not in "\t\n\r" for ch in text):
        return None
    return text


# --- cookie files --------------------------------------------------------------

def parse_cookie_header_text(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    stripped = text.strip()
    if stripped.lower().startswith("cookie:"):
        stripped = stripped.split(":", 1)[1].strip()
    parts = [p.strip() for p in stripped.split(";") if p.strip()]
    for part in parts:
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if name in COOKIE_NAMES or name in ENV_BY_COOKIE.values():
            cookie = name if name in COOKIE_NAMES else next(k for k, v in ENV_BY_COOKIE.items() if v == name)
            val = value.strip()
            if val:
                found[cookie] = val
    return found


def parse_netscape_line(line: str) -> tuple[str, str] | None:
    if not line or line.startswith("#") or line.startswith("//"):
        return None
    raw = line.strip()
    if raw.lower().startswith("cookie:"):
        return None
    if "\t" in raw:
        fields = raw.split("\t")
    else:
        fields = re.split(r"\s+", raw)
    if len(fields) < 7:
        if "=" in raw and "\t" not in raw:
            # env-style NAME=value
            name, value = raw.split("=", 1)
            name = name.strip()
            cookie = None
            if name in COOKIE_NAMES:
                cookie = name
            elif name in ENV_BY_COOKIE.values():
                cookie = next(k for k, v in ENV_BY_COOKIE.items() if v == name)
            if cookie and value.strip():
                return cookie, value.strip()
        return None
    domain, _flag, _path, _secure, _expires, name, value = fields[:7]
    if name not in COOKIE_NAMES:
        return None
    host = domain.lstrip(".").lower()
    if host != "skool.com" and not host.endswith(".skool.com"):
        return None
    if not value:
        return None
    return name, value


def load_cookie_file(path: str) -> tuple[dict[str, str], str]:
    """Return (cookies, kind) where kind is netscape|header|sqlite_rejected."""
    dest = Path(path).expanduser()
    if not dest.is_file():
        raise AuthError(f"SKOOL_COOKIE_FILE is not a readable file ({dest.name}).")
    header = dest.read_bytes()[:16]
    if header.startswith(b"SQLite format 3"):
        raise AuthError(
            "SKOOL_COOKIE_FILE points at a SQLite DB. For Chrome Cookies use "
            "SKOOL_AUTH_MODE=chrome or SKOOL_CHROME_COOKIES_DB, not SKOOL_COOKIE_FILE."
        )
    text = dest.read_text(encoding="utf-8", errors="replace")
    found: dict[str, str] = {}
    lines = text.splitlines() or [text]
    looks_like_header = (
        any(ln.strip().lower().startswith("cookie:") for ln in lines)
        or (";" in text and "\t" not in text and text.count("=") >= 3 and len(lines) <= 3)
    )
    if looks_like_header:
        if len(lines) == 1 or (len(lines) <= 2 and "cookie:" in text.lower()):
            found.update(parse_cookie_header_text(text))
        if len(found) == 3:
            return found, "header"
    for line in lines:
        if line.strip().lower().startswith("cookie:"):
            found.update(parse_cookie_header_text(line))
            continue
        parsed = parse_netscape_line(line)
        if parsed:
            found[parsed[0]] = parsed[1]
    kind = "header" if looks_like_header and "\t" not in text else "netscape"
    return found, kind


# --- Chrome DB -----------------------------------------------------------------

def chrome_cookie_db_candidates() -> list[Path]:
    override = env_value("SKOOL_CHROME_COOKIES_DB")
    if override:
        return [Path(override).expanduser()]
    home = Path.home()
    profile_env = env_value("SKOOL_CHROME_PROFILE")
    profiles = [profile_env] if profile_env else ["Default", "Profile 1"]
    bases: list[Path] = []
    if sys.platform.startswith("linux"):
        bases = [
            home / ".config" / "google-chrome",
            home / ".config" / "chromium",
            home / ".config" / "google-chrome-beta",
        ]
    elif sys.platform == "darwin":
        bases = [
            home / "Library" / "Application Support" / "Google" / "Chrome",
            home / "Library" / "Application Support" / "Chromium",
        ]
    elif sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            bases = [Path(local) / "Google" / "Chrome" / "User Data"]
    paths: list[Path] = []
    for base in bases:
        for profile in profiles:
            paths.append(base / profile / "Network" / "Cookies")
            paths.append(base / profile / "Cookies")
    return paths


def _copy_cookies_db(src: Path) -> tuple[Path, tempfile.TemporaryDirectory[str]]:
    tmp = tempfile.TemporaryDirectory(prefix="skool-chrome-")
    dest = Path(tmp.name) / "Cookies"
    shutil.copy2(src, dest)
    for suffix in ("-wal", "-shm"):
        extra = Path(str(src) + suffix)
        if extra.is_file():
            shutil.copy2(extra, Path(tmp.name) / f"Cookies{suffix}")
    return dest, tmp


def _host_allowed(host: str) -> bool:
    h = (host or "").lower()
    if h in HOST_OK:
        return True
    return h.endswith(".skool.com")


def _row_score(host: str, expires: int) -> tuple[int, int]:
    pref = {"www.skool.com": 0, ".skool.com": 1, "skool.com": 2, ".www.skool.com": 3}
    return (pref.get(host, 9), -int(expires or 0))


def _decode_chrome_value(
    value: str | None,
    encrypted: bytes | None,
    platform: str,
) -> tuple[str | None, str]:
    if value:
        return value, "plaintext"
    blob = encrypted or b""
    if not blob:
        return None, "empty"
    if blob.startswith(b"v10"):
        if platform.startswith("linux"):
            text = chrome_v10_decrypt(blob)
            return text, "v10-peanuts" if text else "v10-decrypt-failed"
        if platform == "darwin":
            return None, "macos-keychain-unsupported"
        if platform == "win32":
            return None, "windows-dpapi-unsupported"
        return None, "v10-unsupported-platform"
    if blob.startswith(b"v11") or blob.startswith(b"v20"):
        return None, "chrome-os-key-unsupported"
    text = _printable_utf8(blob)
    if text:
        return text, "plaintext-blob"
    return None, "encrypted-unknown"


def read_chrome_cookies(db_path: Path | None = None) -> dict[str, Any]:
    platform = sys.platform
    meta: dict[str, Any] = {
        "attempted": True,
        "platform": platform,
        "db_found": False,
        "decrypt": None,
        "note": None,
        "httponly": {name: None for name in COOKIE_NAMES},
        "cookie_expires_at": {name: None for name in COOKIE_NAMES},
    }
    candidates = [db_path] if db_path else chrome_cookie_db_candidates()
    src = next((p for p in candidates if p is not None and p.is_file()), None)
    if src is None:
        meta["note"] = (
            "No Chrome Cookies DB at the well-known Linux/macOS profile paths "
            "(Default / Profile 1, including Network/Cookies). This is OS/profile-fragile "
            "and is not a way to share credentials."
        )
        return {"cookies": {}, "meta": meta}

    meta["db_found"] = True
    meta["db_rel"] = _rel_chrome_path(src)
    tmp_hold: tempfile.TemporaryDirectory[str] | None = None
    try:
        copied, tmp_hold = _copy_cookies_db(src)
        conn = sqlite3.connect(f"file:{copied}?mode=ro", uri=True)
    except OSError:
        try:
            conn = sqlite3.connect(f"file:{src.resolve()}?mode=ro", uri=True)
        except sqlite3.Error:
            meta["note"] = "Chrome Cookies DB exists but could not be opened (Chrome may have it locked)."
            return {"cookies": {}, "meta": meta}
    try:
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT name, value, encrypted_value, host_key, expires_utc, is_httponly "
                "FROM cookies WHERE name IN ('auth_token','client_id','aws-waf-token')"
            ).fetchall()
        except sqlite3.Error:
            meta["note"] = "Chrome Cookies DB is missing the expected cookies table/columns."
            return {"cookies": {}, "meta": meta}
    finally:
        conn.close()
        if tmp_hold is not None:
            tmp_hold.cleanup()

    best: dict[str, sqlite3.Row] = {}
    best_score: dict[str, tuple[int, int]] = {}
    for row in rows:
        name = row["name"]
        host = row["host_key"] or ""
        if name not in COOKIE_NAMES or not _host_allowed(host):
            continue
        score = _row_score(host, int(row["expires_utc"] or 0))
        if name not in best or score < best_score[name]:
            best[name] = row
            best_score[name] = score

    cookies: dict[str, str] = {}
    decrypt_tags: list[str] = []
    for name, row in best.items():
        try:
            httponly = bool(row["is_httponly"])
        except (KeyError, IndexError):
            httponly = None
        meta["httponly"][name] = httponly
        expires = _chrome_expires_iso(row["expires_utc"])
        meta["cookie_expires_at"][name] = expires
        enc = row["encrypted_value"]
        if isinstance(enc, memoryview):
            enc = enc.tobytes()
        if isinstance(enc, str):
            enc = enc.encode("latin1")
        text, tag = _decode_chrome_value(row["value"] if "value" in row.keys() else None, enc, platform)
        decrypt_tags.append(tag)
        if text:
            cookies[name] = text

    if decrypt_tags:
        meta["decrypt"] = decrypt_tags[0] if len(set(decrypt_tags)) == 1 else ",".join(sorted(set(decrypt_tags)))
    if not cookies:
        if platform == "darwin":
            meta["note"] = (
                "macOS Chrome encrypts cookies with Keychain; this stdlib plugin does not "
                "unlock Keychain. Use portable paste (A) or export a Netscape cookie file to SKOOL_COOKIE_FILE."
            )
        elif platform == "win32":
            meta["note"] = (
                "Windows Chrome cookies need DPAPI, which this stdlib plugin does not implement. "
                "Use portable paste (A) or SKOOL_COOKIE_FILE."
            )
        elif meta.get("decrypt") == "v10-decrypt-failed":
            meta["note"] = (
                "Linux Chrome v10 decrypt failed (not the peanuts key — often v11/libsecret). "
                "Use portable paste or SKOOL_COOKIE_FILE."
            )
        elif meta.get("decrypt") == "chrome-os-key-unsupported":
            meta["note"] = (
                "Chrome cookie blob is v11/v20 (OS keyring / app-bound). "
                "Use portable paste or SKOOL_COOKIE_FILE."
            )
        else:
            meta["note"] = "Chrome DB opened but the three Skool cookies were not found or not decryptable."
    elif platform == "darwin" and len(cookies) < 3:
        meta["note"] = (
            "Partial Chrome read on macOS. Remaining cookies are likely Keychain-encrypted — "
            "use portable paste or SKOOL_COOKIE_FILE for those."
        )
    return {"cookies": cookies, "meta": meta}


def _rel_chrome_path(path: Path) -> str:
    home = Path.home()
    try:
        rel = path.resolve().relative_to(home)
        return str(Path("~") / rel)
    except ValueError:
        return path.name


def _chrome_expires_iso(expires_utc: Any) -> str | None:
    try:
        ticks = int(expires_utc)
    except (TypeError, ValueError):
        return None
    if ticks <= 0:
        return None
    unix = ticks / 1_000_000 - _CHROME_EPOCH_DELTA
    if unix <= 0:
        return None
    try:
        return datetime.fromtimestamp(unix, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


# --- resolve -------------------------------------------------------------------

@dataclass
class Session:
    source: str
    cookies: dict[str, str] = field(default_factory=dict)
    httponly: dict[str, bool | None] = field(
        default_factory=lambda: {name: None for name in COOKIE_NAMES}
    )
    chrome: dict[str, Any] = field(default_factory=dict)
    cookie_file_kind: str | None = None
    note: str | None = None

    @property
    def complete(self) -> bool:
        return all(self.cookies.get(name) for name in COOKIE_NAMES)

    def present_flags(self) -> dict[str, bool]:
        return {name: bool(self.cookies.get(name)) for name in COOKIE_NAMES}

    def env_flags(self) -> dict[str, bool]:
        return {env_name: env_value(env_name) is not None for env_name in SECRET_ENV}


def resolve_session() -> Session:
    env = env_cookies()
    if all(env.get(name) for name in COOKIE_NAMES):
        return Session(source="env", cookies=dict(env))

    cookie_path = env_value("SKOOL_COOKIE_FILE")
    if cookie_path:
        try:
            file_cookies, kind = load_cookie_file(cookie_path)
        except AuthError as exc:
            return Session(source="missing", note=str(exc))
        if all(file_cookies.get(name) for name in COOKIE_NAMES):
            return Session(source="cookie_file", cookies=file_cookies, cookie_file_kind=kind)
        return Session(
            source="missing",
            cookies=file_cookies,
            cookie_file_kind=kind,
            note="SKOOL_COOKIE_FILE did not contain all three Skool cookies (auth_token, client_id, aws-waf-token).",
        )

    if chrome_mode_enabled():
        result = read_chrome_cookies()
        cookies = result["cookies"]
        meta = result["meta"]
        source = "chrome" if all(cookies.get(n) for n in COOKIE_NAMES) else "missing"
        return Session(
            source=source,
            cookies=cookies,
            httponly=meta.get("httponly") or {n: None for n in COOKIE_NAMES},
            chrome=meta,
            note=meta.get("note"),
        )

    note = None
    if env:
        missing = [ENV_BY_COOKIE[n] for n in COOKIE_NAMES if n not in env]
        note = (
            "Some plugin env cookies are set but not all three. "
            f"Missing: {', '.join(missing)}. Complete portable paste, or set SKOOL_AUTH_MODE=chrome / SKOOL_COOKIE_FILE."
        )
    return Session(source="missing", cookies=env, note=note)


def missing_cookie_env_names(session: Session | None = None) -> list[str]:
    sess = session or resolve_session()
    return [ENV_BY_COOKIE[name] for name in COOKIE_NAMES if not sess.cookies.get(name)]


def require_session() -> Session:
    session = resolve_session()
    if session.complete:
        return session
    missing = missing_cookie_env_names(session)
    bits = [
        "Missing Skool session cookies: " + ", ".join(missing) + ".",
        "Portable: paste auth_token, client_id, aws-waf-token under Plugins → Configure.",
        "Same machine: SKOOL_AUTH_MODE=chrome (Linux v10 only) or SKOOL_COOKIE_FILE.",
    ]
    if session.note:
        bits.append(session.note)
    raise AuthError(" ".join(bits))


def cookie_header() -> str:
    session = require_session()
    return (
        f"auth_token={session.cookies['auth_token']}; "
        f"client_id={session.cookies['client_id']}; "
        f"aws-waf-token={session.cookies['aws-waf-token']}"
    )


def auth_status_payload() -> dict[str, Any]:
    session = resolve_session()
    out: dict[str, Any] = {
        "source": session.source,
        "env": session.env_flags(),
        "present": session.present_flags(),
        "SKOOL_COMMUNITY_SLUG_present": env_value("SKOOL_COMMUNITY_SLUG") is not None,
        "chrome_mode": chrome_mode_enabled(),
        "cookie_file_configured": env_value("SKOOL_COOKIE_FILE") is not None,
    }
    if session.cookie_file_kind:
        out["cookie_file_kind"] = session.cookie_file_kind
    if session.chrome:
        chrome_pub = {
            k: session.chrome.get(k)
            for k in ("attempted", "platform", "db_found", "decrypt", "note", "httponly", "db_rel")
            if k in session.chrome and session.chrome.get(k) is not None
        }
        expires = session.chrome.get("cookie_expires_at")
        if expires:
            chrome_pub["cookie_expires_at"] = expires
        out["chrome"] = chrome_pub
    if session.note and session.source == "missing":
        out["note"] = session.note
    token = session.cookies.get("auth_token")
    if token:
        info = jwt_expiry(token)
        out["auth_token_jwt_parsable"] = info["jwt_parsable"]
        out["expired"] = info["expired"]
        out["expires_at"] = info["expires_at"]
        out["not_expired"] = (info["expired"] is False) if info["jwt_parsable"] else None
    else:
        out["auth_token_jwt_parsable"] = False
        out["expired"] = None
        out["expires_at"] = None
        out["not_expired"] = None
        cookie_exp = (session.chrome or {}).get("cookie_expires_at") or {}
        if cookie_exp.get("auth_token"):
            out["expires_at"] = cookie_exp["auth_token"]
    return out
