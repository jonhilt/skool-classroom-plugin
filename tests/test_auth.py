import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import auth
import server


FAKE = {
    "auth_token": "fake-env-auth-token-not-a-real-jwt",
    "client_id": "fake-env-client-id",
    "aws-waf-token": "fake-env-waf-token",
}


def _fake_jwt(exp: int = 4102444800) -> str:
    payload = json.dumps({"exp": exp}).encode("utf-8")
    b64 = __import__("base64").urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"eyJhbGciOiJub25lIn0.{b64}.sig"


def _clear_auth_env() -> dict[str, str]:
    return {
        "SKOOL_AUTH_TOKEN": "",
        "SKOOL_CLIENT_ID": "",
        "SKOOL_AWS_WAF_TOKEN": "",
        "SKOOL_AUTH_MODE": "",
        "SKOOL_USE_CHROME": "",
        "SKOOL_COOKIE_FILE": "",
        "SKOOL_CHROME_COOKIES_DB": "",
        "SKOOL_CHROME_PROFILE": "",
    }


def _assert_no_secrets(blob: str, *secrets: str) -> None:
    for secret in secrets:
        if secret:
            assert secret not in blob, f"leaked secret fragment in status: {secret[:8]}…"


class AesTests(unittest.TestCase):
    def test_nist_aes128_block(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(auth.aes128_encrypt_block(key, pt), ct)
        self.assertEqual(auth.aes128_decrypt_block(key, ct), pt)

    def test_chrome_v10_roundtrip(self):
        blob = auth.chrome_v10_encrypt(b"fake-chrome-v10-value")
        self.assertTrue(blob.startswith(b"v10"))
        self.assertEqual(auth.chrome_v10_decrypt(blob), "fake-chrome-v10-value")


class AuthStatusEnvTests(unittest.TestCase):
    def test_missing_source_and_message(self):
        with mock.patch.dict(os.environ, _clear_auth_env(), clear=True):
            status = server.tool_auth_status({})
            self.assertEqual(status["source"], "missing")
            self.assertFalse(status["env"]["SKOOL_AUTH_TOKEN"])
            self.assertFalse(status["present"]["auth_token"])
            with self.assertRaises(server.ToolError) as ctx:
                server.require_secrets()
            msg = str(ctx.exception)
            self.assertIn("Plugins → Configure", msg)
            self.assertIn("SKOOL_AUTH_MODE=chrome", msg)
            self.assertIn("SKOOL_COOKIE_FILE", msg)
            self.assertNotIn("never reads browser cookie databases", msg)

    def test_placeholder_env_is_absent(self):
        env = _clear_auth_env()
        env.update(
            {
                "SKOOL_AUTH_TOKEN": "${SKOOL_AUTH_TOKEN}",
                "SKOOL_CLIENT_ID": "   ",
                "SKOOL_AWS_WAF_TOKEN": "${SKOOL_AWS_WAF_TOKEN}",
            }
        )
        with mock.patch.dict(os.environ, env, clear=True):
            status = server.tool_auth_status({})
            self.assertEqual(status["source"], "missing")
            self.assertFalse(status["env"]["SKOOL_AUTH_TOKEN"])
            self.assertFalse(status["env"]["SKOOL_CLIENT_ID"])
            self.assertFalse(status["env"]["SKOOL_AWS_WAF_TOKEN"])
            self.assertIsNone(status["not_expired"])

    def test_fake_env_source_env_no_leak(self):
        token = _fake_jwt()
        env = _clear_auth_env()
        env.update(
            {
                "SKOOL_AUTH_TOKEN": token,
                "SKOOL_CLIENT_ID": FAKE["client_id"],
                "SKOOL_AWS_WAF_TOKEN": FAKE["aws-waf-token"],
            }
        )
        with mock.patch.dict(os.environ, env, clear=True):
            status = server.tool_auth_status({})
            self.assertEqual(status["source"], "env")
            self.assertTrue(status["present"]["auth_token"])
            self.assertTrue(status["env"]["SKOOL_AUTH_TOKEN"])
            self.assertFalse(status["expired"])
            blob = json.dumps(status)
            _assert_no_secrets(blob, token, FAKE["client_id"], FAKE["aws-waf-token"])

    def test_env_wins_over_chrome_and_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cookie_file = Path(tmp) / "cookies.txt"
            cookie_file.write_text(
                "auth_token=file-token\nclient_id=file-client\naws-waf-token=file-waf\n",
                encoding="utf-8",
            )
            env = _clear_auth_env()
            env.update(
                {
                    "SKOOL_AUTH_TOKEN": FAKE["auth_token"],
                    "SKOOL_CLIENT_ID": FAKE["client_id"],
                    "SKOOL_AWS_WAF_TOKEN": FAKE["aws-waf-token"],
                    "SKOOL_AUTH_MODE": "chrome",
                    "SKOOL_COOKIE_FILE": str(cookie_file),
                }
            )
            with mock.patch.dict(os.environ, env, clear=True):
                status = server.tool_auth_status({})
                self.assertEqual(status["source"], "env")
                header = server.cookie_header()
                self.assertIn("fake-env-auth-token", header)
                blob = json.dumps(status)
                _assert_no_secrets(blob, FAKE["auth_token"], "file-token")


class CookieFileTests(unittest.TestCase):
    def test_netscape_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cookies.txt"
            path.write_text(
                "# Netscape HTTP Cookie File\n"
                ".skool.com\tTRUE\t/\tTRUE\t1780000000\tauth_token\tfake-file-auth\n"
                ".skool.com\tTRUE\t/\tTRUE\t1780000000\tclient_id\tfake-file-client\n"
                ".skool.com\tTRUE\t/\tTRUE\t1780000000\taws-waf-token\tfake-file-waf\n",
                encoding="utf-8",
            )
            env = _clear_auth_env()
            env["SKOOL_COOKIE_FILE"] = str(path)
            with mock.patch.dict(os.environ, env, clear=True):
                status = server.tool_auth_status({})
                self.assertEqual(status["source"], "cookie_file")
                self.assertEqual(status["cookie_file_kind"], "netscape")
                self.assertTrue(status["present"]["client_id"])
                blob = json.dumps(status)
                _assert_no_secrets(blob, "fake-file-auth", "fake-file-client", "fake-file-waf")
                header = server.cookie_header()
                self.assertIn("fake-file-auth", header)

    def test_cookie_header_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "header.txt"
            path.write_text(
                "Cookie: auth_token=fake-hdr-auth; client_id=fake-hdr-client; aws-waf-token=fake-hdr-waf\n",
                encoding="utf-8",
            )
            env = _clear_auth_env()
            env["SKOOL_COOKIE_FILE"] = str(path)
            with mock.patch.dict(os.environ, env, clear=True):
                status = server.tool_auth_status({})
                self.assertEqual(status["source"], "cookie_file")
                blob = json.dumps(status)
                _assert_no_secrets(blob, "fake-hdr-auth", "fake-hdr-client")

    def test_sqlite_rejected_as_cookie_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Cookies"
            conn = sqlite3.connect(path)
            conn.execute("CREATE TABLE t (id INTEGER)")
            conn.commit()
            conn.close()
            env = _clear_auth_env()
            env["SKOOL_COOKIE_FILE"] = str(path)
            with mock.patch.dict(os.environ, env, clear=True):
                status = server.tool_auth_status({})
                self.assertEqual(status["source"], "missing")
                self.assertIn("SQLite", status.get("note") or "")


def _write_chrome_db(path: Path, rows: list[tuple]) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE cookies (
            host_key TEXT,
            name TEXT,
            value TEXT,
            encrypted_value BLOB,
            path TEXT,
            expires_utc INTEGER,
            is_httponly INTEGER
        )
        """
    )
    conn.executemany(
        "INSERT INTO cookies VALUES (?,?,?,?,?,?,?)",
        rows,
    )
    conn.commit()
    conn.close()


class ChromeDbTests(unittest.TestCase):
    def test_plaintext_chrome_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "Cookies"
            _write_chrome_db(
                db,
                [
                    (".skool.com", "auth_token", "fake-chrome-auth", b"", "/", 0, 1),
                    (".skool.com", "client_id", "fake-chrome-client", b"", "/", 0, 0),
                    (".skool.com", "aws-waf-token", "fake-chrome-waf", b"", "/", 0, 0),
                ],
            )
            env = _clear_auth_env()
            env.update(
                {
                    "SKOOL_AUTH_MODE": "chrome",
                    "SKOOL_CHROME_COOKIES_DB": str(db),
                }
            )
            with mock.patch.dict(os.environ, env, clear=True):
                status = server.tool_auth_status({})
                self.assertEqual(status["source"], "chrome")
                self.assertTrue(status["chrome"]["db_found"])
                self.assertTrue(status["present"]["auth_token"])
                self.assertEqual(status["chrome"]["httponly"]["auth_token"], True)
                blob = json.dumps(status)
                _assert_no_secrets(
                    blob, "fake-chrome-auth", "fake-chrome-client", "fake-chrome-waf"
                )

    def test_linux_v10_chrome_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "Cookies"
            enc_auth = auth.chrome_v10_encrypt(b"fake-v10-auth")
            enc_client = auth.chrome_v10_encrypt(b"fake-v10-client")
            enc_waf = auth.chrome_v10_encrypt(b"fake-v10-waf")
            _write_chrome_db(
                db,
                [
                    ("www.skool.com", "auth_token", "", enc_auth, "/", 0, 1),
                    ("www.skool.com", "client_id", "", enc_client, "/", 0, 0),
                    ("www.skool.com", "aws-waf-token", "", enc_waf, "/", 0, 0),
                ],
            )
            env = _clear_auth_env()
            env.update(
                {
                    "SKOOL_AUTH_MODE": "chrome",
                    "SKOOL_CHROME_COOKIES_DB": str(db),
                }
            )
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(auth.sys, "platform", "linux"):
                    status = server.tool_auth_status({})
                    self.assertEqual(status["source"], "chrome")
                    self.assertIn("v10", status["chrome"].get("decrypt") or "")
                    header = server.cookie_header()
                    self.assertIn("fake-v10-auth", header)
                    blob = json.dumps(status)
                    _assert_no_secrets(blob, "fake-v10-auth", "fake-v10-client", "fake-v10-waf")

    def test_chrome_not_used_without_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "Cookies"
            _write_chrome_db(
                db,
                [(".skool.com", "auth_token", "fake-chrome-auth", b"", "/", 0, 1)],
            )
            env = _clear_auth_env()
            env["SKOOL_CHROME_COOKIES_DB"] = str(db)
            with mock.patch.dict(os.environ, env, clear=True):
                status = server.tool_auth_status({})
                self.assertEqual(status["source"], "missing")
                self.assertFalse(status["present"]["auth_token"])

    def test_macos_v10_not_decrypted(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "Cookies"
            enc = auth.chrome_v10_encrypt(b"fake-mac-auth")
            _write_chrome_db(
                db,
                [
                    (".skool.com", "auth_token", "", enc, "/", 0, 1),
                    (".skool.com", "client_id", "", enc, "/", 0, 0),
                    (".skool.com", "aws-waf-token", "", enc, "/", 0, 0),
                ],
            )
            env = _clear_auth_env()
            env.update({"SKOOL_AUTH_MODE": "chrome", "SKOOL_CHROME_COOKIES_DB": str(db)})
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(auth.sys, "platform", "darwin"):
                    status = server.tool_auth_status({})
                    self.assertEqual(status["source"], "missing")
                    note = (status.get("note") or "") + json.dumps(status.get("chrome") or {})
                    self.assertIn("Keychain", note)
                    blob = json.dumps(status)
                    _assert_no_secrets(blob, "fake-mac-auth")


class JwtTests(unittest.TestCase):
    def test_jwt_exp_without_printing_token(self):
        token = _fake_jwt()
        info = server.jwt_expiry(token)
        self.assertTrue(info["jwt_parsable"])
        self.assertFalse(info["expired"])
        dumped = json.dumps(info)
        self.assertNotIn(token, dumped)
        self.assertNotIn(token.split(".")[1], dumped)


if __name__ == "__main__":
    unittest.main()
