import json
import os
import unittest
from unittest import mock

import server


class TiptapTests(unittest.TestCase):
    def test_markdown_heading_bold_list(self):
        md = "# Title\n\nHello **bold** and *ital*.\n\n- one\n- two\n"
        nodes = server.markdown_to_tiptap(md)
        types = [n["type"] for n in nodes]
        self.assertIn("heading", types)
        self.assertIn("bulletList", types)
        heading = next(n for n in nodes if n["type"] == "heading")
        self.assertEqual(heading["attrs"]["level"], 2)
        encoded = server.encode_desc(nodes)
        self.assertTrue(encoded.startswith("[v2]["))
        json.loads(encoded[len("[v2]"):])
        roundtrip = server.tiptap_to_markdown(nodes)
        self.assertIn("**bold**", roundtrip)
        self.assertIn("- one", roundtrip)

    def test_v2_passthrough(self):
        raw = '[v2][{"type":"paragraph","content":[{"type":"text","text":"Hi"}]}]'
        desc = server.body_to_desc(raw)
        self.assertEqual(desc, '[v2][{"type":"paragraph","content":[{"type":"text","text":"Hi"}]}]')
        md = server.tiptap_to_markdown(server.parse_desc_nodes(desc))
        self.assertEqual(md.strip(), "Hi")

    def test_invalid_v2_raises(self):
        with self.assertRaises(server.ToolError):
            server.body_to_desc("[v2]{not-json")


class AuthAndDryRunTests(unittest.TestCase):
    def test_missing_secrets_message(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(server.ToolError) as ctx:
                server.require_secrets()
            msg = str(ctx.exception)
            self.assertIn("SKOOL_AUTH_TOKEN", msg)
            self.assertIn("Plugins → Configure", msg)
            self.assertIn("SKOOL_AUTH_MODE=chrome", msg)

    def test_placeholder_env_is_absent(self):
        env = {
            "SKOOL_AUTH_TOKEN": "${SKOOL_AUTH_TOKEN}",
            "SKOOL_CLIENT_ID": "   ",
            "SKOOL_AWS_WAF_TOKEN": "${SKOOL_AWS_WAF_TOKEN}",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            status = server.tool_auth_status({})
            self.assertFalse(status["env"]["SKOOL_AUTH_TOKEN"])
            self.assertEqual(status["source"], "missing")
            self.assertFalse(status["env"]["SKOOL_CLIENT_ID"])
            self.assertFalse(status["env"]["SKOOL_AWS_WAF_TOKEN"])
            self.assertIsNone(status["not_expired"])

    def test_jwt_exp_without_printing_token(self):
        payload = json.dumps({"exp": 4102444800}).encode("utf-8")  # 2100-01-01
        b64 = __import__("base64").urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        token = f"eyJhbGciOiJub25lIn0.{b64}.sig"
        info = server.jwt_expiry(token)
        self.assertTrue(info["jwt_parsable"])
        self.assertFalse(info["expired"])
        dumped = json.dumps(info)
        self.assertNotIn(token, dumped)
        self.assertNotIn(b64, dumped)

    def test_dry_run_default_true(self):
        self.assertTrue(server._dry_run_flag({}))
        self.assertTrue(server._dry_run_flag({"dry_run": True}))
        self.assertFalse(server._dry_run_flag({"dry_run": False}))
        self.assertFalse(server._dry_run_flag({"dry_run": "false"}))

    def test_auth_status_booleans_only(self):
        env = {
            "SKOOL_AUTH_TOKEN": "not-a-jwt",
            "SKOOL_CLIENT_ID": "fake-client-xyz",
            "SKOOL_AWS_WAF_TOKEN": "fake-waf-xyz",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            status = server.tool_auth_status({})
            self.assertTrue(status["env"]["SKOOL_AUTH_TOKEN"])
            self.assertEqual(status["source"], "env")
            blob = json.dumps(status)
            self.assertNotIn("not-a-jwt", blob)
            self.assertNotIn("fake-client-xyz", blob)
            self.assertNotIn("fake-waf-xyz", blob)


class WriteGuardTests(unittest.TestCase):
    def test_module_put_keys_only_title_desc(self):
        captured = {}

        def fake_api(path, method="GET", payload=None, slug=None):
            captured["path"] = path
            captured["method"] = method
            captured["payload"] = payload
            return {"ok": True}

        with mock.patch.object(server, "api_json", fake_api):
            server.put_module("deadbeefdeadbeefdeadbeefdeadbeef", "Lesson", "[v2][]", None)
        self.assertEqual(captured["method"], "PUT")
        self.assertEqual(set(captured["payload"]), {"title", "desc"})

    def test_course_root_refused_on_set(self):
        def fake_load(lesson_id, slug=None):
            return (
                {
                    "id": lesson_id,
                    "unit_type": "course",
                    "metadata": {"title": "Course", "state": 1, "privacy": 2},
                },
                [],
                {},
            )

        with mock.patch.object(server, "load_unit", fake_load):
            with mock.patch.object(server, "require_secrets"):
                with self.assertRaises(server.ToolError) as ctx:
                    server.tool_lesson_set(
                        {"lesson_id": "aa" * 16, "body": "hi", "dry_run": False}
                    )
        self.assertIn("course root", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
