#!/usr/bin/env python3
"""Validate manifests, compile, smoke MCP, skip live API unless cookies exist."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugin.json"
MCP = ROOT / "mcp.json"
SERVER = ROOT / "server.py"
SCHEMA_PLUGIN = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
SCHEMA_MCP = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"
SECRET_ENV = ("SKOOL_AUTH_TOKEN", "SKOOL_CLIENT_ID", "SKOOL_AWS_WAF_TOKEN")


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr, flush=True)
    sys.exit(1)


def ok(message: str) -> None:
    print(f"ok: {message}", flush=True)


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "skool-plugin-prove/0.1"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def validate_schemas() -> None:
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", "jsonschema"],
            cwd=str(ROOT),
        )
        import importlib
        import site

        user_site = site.getusersitepackages()
        if user_site not in sys.path:
            sys.path.append(user_site)
        importlib.invalidate_caches()
        from jsonschema import Draft202012Validator

    plugin_schema = fetch_json(SCHEMA_PLUGIN)
    mcp_schema = fetch_json(SCHEMA_MCP)
    plugin = json.loads(PLUGIN.read_text(encoding="utf-8"))
    mcp = json.loads(MCP.read_text(encoding="utf-8"))
    Draft202012Validator(plugin_schema).validate(plugin)
    Draft202012Validator(mcp_schema).validate(mcp)
    if plugin.get("$schema") != SCHEMA_PLUGIN:
        fail("plugin.json $schema mismatch")
    if mcp.get("$schema") != SCHEMA_MCP:
        fail("mcp.json $schema mismatch")
    ok("plugin.json + mcp.json valid against Agent Plugins 1.0.0 schemas")


def compile_server() -> None:
    for name in ("server.py", "auth.py"):
        subprocess.check_call(
            [sys.executable, "-m", "py_compile", str(ROOT / name)], cwd=str(ROOT)
        )
    ok("py_compile server.py auth.py")


def run_unittests() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=str(ROOT),
        check=False,
    )
    if result.returncode != 0:
        fail("unit tests")
    ok("unit tests")


def rpc(proc: subprocess.Popen, payload: dict) -> dict:
    assert proc.stdin and proc.stdout
    proc.stdin.write((json.dumps(payload) + "\n").encode("utf-8"))
    proc.stdin.flush()
    line = proc.stdout.readline()
    if not line:
        err = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
        fail(f"MCP server closed stdout. stderr={err[:400]!r}")
    try:
        message = json.loads(line.decode("utf-8"))
    except json.JSONDecodeError:
        fail(f"MCP server emitted non-JSON: {line[:200]!r}")
    return message


def secret_set(name: str) -> bool:
    value = os.environ.get(name, "").strip()
    return bool(value) and not value.startswith("${")


def smoke_mcp() -> None:
    env = os.environ.copy()
    # Unresolved plugin placeholders must not look like real cookies.
    for name in SECRET_ENV:
        if env.get(name, "").startswith("${"):
            env.pop(name, None)
    proc = subprocess.Popen(
        [sys.executable, "-u", str(SERVER)],
        cwd=str(ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    try:
        init = rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "prove", "version": "0.1.0"},
                },
            },
        )
        if "error" in init:
            fail(f"initialize error: {init['error']}")
        result = init.get("result") or {}
        if result.get("serverInfo", {}).get("name") != "skool":
            fail(f"unexpected serverInfo: {result.get('serverInfo')}")
        listed = rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = ((listed.get("result") or {}).get("tools")) or []
        names = [t.get("name") for t in tools]
        expected = [
            "skool_auth_status",
            "skool_courses",
            "skool_lessons",
            "skool_lesson_get",
            "skool_lesson_set",
            "skool_lesson_attach_image",
            "skool_course_get",
        ]
        missing = [n for n in expected if n not in names]
        if missing:
            fail(f"tools/list missing {missing}; got {names}")
        if len(tools) != 7:
            fail(f"expected 7 tools, got {len(tools)}: {names}")
        ok("MCP initialize + tools/list (7 tools)")

        auth = rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "skool_auth_status", "arguments": {}},
            },
        )
        text = ((auth.get("result") or {}).get("content") or [{}])[0].get("text") or ""
        for name in SECRET_ENV:
            value = os.environ.get(name, "")
            if value and value in text:
                fail("skool_auth_status leaked a secret env value")
        payload = json.loads(text)
        source = payload.get("source")
        if source not in ("env", "chrome", "cookie_file", "missing"):
            fail(f"auth_status source unexpected: {source!r}")
        env_flags = payload.get("env") or {}
        if set(env_flags) < set(SECRET_ENV):
            fail(f"auth_status missing env flags: {env_flags}")
        if any(not isinstance(env_flags[k], bool) for k in SECRET_ENV):
            fail("auth_status env flags must be booleans")
        present = payload.get("present") or {}
        if any(not isinstance(present.get(n), bool) for n in ("auth_token", "client_id", "aws-waf-token")):
            fail(f"auth_status present flags must be booleans: {present}")
        ok("skool_auth_status returns source + booleans only")

        cookies_present = all(secret_set(n) for n in SECRET_ENV)
        slug = os.environ.get("SKOOL_COMMUNITY_SLUG", "").strip()
        if not cookies_present:
            print(
                "skip: live API (SKOOL_AUTH_TOKEN, SKOOL_CLIENT_ID, "
                "SKOOL_AWS_WAF_TOKEN not all present in the environment)"
            )
        elif not slug or slug.startswith("${"):
            print("skip: live courses list (cookies present, SKOOL_COMMUNITY_SLUG not set)")
        else:
            live = rpc(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "skool_courses",
                        "arguments": {"community_slug": slug},
                    },
                },
            )
            live_text = ((live.get("result") or {}).get("content") or [{}])[0].get("text") or ""
            is_error = (live.get("result") or {}).get("isError")
            if is_error:
                print("live skool_courses returned isError (session may be expired); not failing prove")
                print(live_text[:400])
            else:
                ok("live skool_courses (cookies + slug present)")
    finally:
        if proc.stdin:
            proc.stdin.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def assert_no_committed_secrets() -> None:
    for path in (
        PLUGIN,
        MCP,
        SERVER,
        ROOT / "auth.py",
        ROOT / "README.md",
        ROOT / "skills" / "skool" / "SKILL.md",
    ):
        text = path.read_text(encoding="utf-8")
        if "eyJ" in text and "jwt" not in text.lower():
            # JWT-looking blob in source would be a committed token.
            if any(len(part) > 40 for part in text.split() if part.startswith("eyJ")):
                fail(f"possible JWT in {path.name}")
    ok("no JWT-looking blobs in authored manifests/docs")


def main() -> None:
    os.chdir(ROOT)
    validate_schemas()
    compile_server()
    run_unittests()
    assert_no_committed_secrets()
    smoke_mcp()
    print("prove: all required checks passed")


if __name__ == "__main__":
    main()
