"""Tests for data_sanitizer.core — the core sanitization logic."""

import json
import os
import sys
import re

import pytest

# Ensure src is on the path for direct test execution
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from data_sanitizer import sanitize, sanitize_json, PATTERNS


# ============================================================
# Sanitize — single-string tests
# ============================================================


class TestSanitize:
    def test_api_key(self):
        assert sanitize("sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456") == "[API_KEY_REDACTED]"

    def test_github_token(self):
        assert sanitize("ghp_abcdefghijklmnopqrstuvwxyz1234567890") == "[GITHUB_TOKEN_REDACTED]"

    def test_slack_token(self):
        assert sanitize("xoxb-FAKE_SLACK_TOKEN_12345678901234567890") == "[SLACK_TOKEN_REDACTED]"

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8"
        assert sanitize(jwt) == "[JWT_REDACTED]"

    def test_local_path_windows(self):
        assert sanitize(r"D:\Work\ForAI\AniMind\config.yaml") == "[LOCAL_PATH_REDACTED]"

    def test_env_var_leak(self):
        assert sanitize("WECHAT_APPID=wx_TEST_APP_ID_12345678") == "[ENV_VAL_REDACTED]"

    def test_private_ip_10(self):
        assert sanitize("10.0.0.1") == "[PRIVATE_IP_REDACTED]"

    def test_private_ip_192(self):
        assert sanitize("192.168.1.100") == "[PRIVATE_IP_REDACTED]"

    def test_private_ip_172(self):
        assert sanitize("172.16.0.1") == "[PRIVATE_IP_REDACTED]"

    def test_phone_cn(self):
        assert sanitize("13800138000") == "[PHONE_CN_REDACTED]"

    def test_non_string_passthrough(self):
        assert sanitize(42) == 42
        assert sanitize(None) is None
        assert sanitize([1, 2, 3]) == [1, 2, 3]

    def test_no_false_positive_on_short_strings(self):
        """Short strings that look like tokens but aren't should pass through."""
        assert sanitize("sk-") == "sk-"
        assert sanitize("ghp_abc") == "ghp_abc"

    def test_mixed_content(self):
        text = (
            "My key: sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456, "
            "path: D:\\Work\\project\\file.txt, "
            "IP: 192.168.1.1"
        )
        result = sanitize(text)
        assert "[API_KEY_REDACTED]" in result
        assert "[LOCAL_PATH_REDACTED]" in result
        assert "[PRIVATE_IP_REDACTED]" in result
        assert "sk-proj" not in result

    def test_chinese_context(self):
        """\b fails on CJK text; must use ASCII-aware boundaries."""
        text = r"是sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456，路径D:\Work\里"
        result = sanitize(text)
        assert "[API_KEY_REDACTED]" in result, \
            f"API Key not redacted in CJK context: {result}"
        assert "[LOCAL_PATH_REDACTED]" in result, \
            f"Path not redacted in CJK context: {result}"

    def test_chinese_context_full_message(self):
        """Simulate a real chat message with CJK + secrets."""
        text = (
            "我的API Key是sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456，\n"
            "GitHub token是ghp_abcdefghijklmnopqrstuvwxyz1234567890，\n"
            "路径是D:\\Work\\ForAI\\AniMind\\config.yaml，\n"
            "IP是192.168.1.100，\n手机13800138000"
        )
        result = sanitize(text)
        assert "sk-proj" not in result
        assert "ghp_" not in result
        assert "D:\\Work\\ForAI" not in result
        assert "192.168.1.100" not in result
        assert "13800138000" not in result
        assert "[API_KEY_REDACTED]" in result
        assert "[GITHUB_TOKEN_REDACTED]" in result
        assert "[LOCAL_PATH_REDACTED]" in result
        assert "[PRIVATE_IP_REDACTED]" in result
        assert "[PHONE_CN_REDACTED]" in result


# ============================================================
# Sanitize JSON — recursive object tests
# ============================================================


class TestSanitizeJson:
    def test_flat_dict(self):
        data = {"text": "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456", "count": 3}
        result = sanitize_json(data)
        assert result["text"] == "[API_KEY_REDACTED]"
        assert result["count"] == 3

    def test_nested_dict(self):
        data = {"user": {"note": "key is sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456"}}
        result = sanitize_json(data)
        assert result["user"]["note"] == "key is [API_KEY_REDACTED]"

    def test_list_of_strings(self):
        data = ["sk-1111111111111111111111", "sk-2222222222222222222222"]
        result = sanitize_json(data)
        assert all(v == "[API_KEY_REDACTED]" for v in result)

    def test_list_of_dicts(self):
        data = [{"msg": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"}]
        result = sanitize_json(data)
        assert result[0]["msg"] == "[GITHUB_TOKEN_REDACTED]"

    def test_lark_cli_output(self):
        """Simulate the real output format from lark-cli."""
        data = {
            "data": {
                "items": [
                    {
                        "sender": {"id": "ou_xxxx"},
                        "body": {"content": "my ip 192.168.1.100"},
                    }
                ],
                "has_more": False,
            }
        }
        result = sanitize_json(data)
        assert "[PRIVATE_IP_REDACTED]" in result["data"]["items"][0]["body"]["content"]


# ============================================================
# Pattern list
# ============================================================


class TestPatterns:
    def test_pattern_count(self):
        assert len(PATTERNS) >= 8, "Should have at least 8 default patterns"

    def test_all_patterns_compile(self):
        for label, regex in PATTERNS:
            try:
                import re
                re.compile(regex)
            except re.error as e:
                pytest.fail(f"Pattern '{label}' failed to compile: {e}")

    def test_cjk_boundary(self):
        """Verify all boundary-using patterns work in CJK context."""
        cjk_tests = [
            ("API_KEY", "是sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456"),
            ("GITHUB_TOKEN", "是ghp_abcdefghijklmnopqrstuvwxyz1234567890"),
            ("JWT", "是eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8"),
            ("PRIVATE_IP", "IP是192.168.1.100"),
            ("PHONE_CN", "手机13800138000"),
        ]
        for label, text in cjk_tests:
            result = sanitize(text)
            assert f"[{label}_REDACTED]" in result, \
                f"[{label}_REDACTED] not found in CJK context. Got: {result}"
