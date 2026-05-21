#!/usr/bin/env python3
"""Basic usage examples for data-sanitizer."""

from data_sanitizer import sanitize, sanitize_json

# --- Single string ---
examples = [
    ("API Key",       "My key is sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456"),
    ("GitHub Token",  "ghp_abcdefghijklmnopqrstuvwxyz1234567890"),
    ("JWT",           "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8"),
    ("Local Path",    r"Config at D:\Work\ForAI\AniMind\config.yaml"),
    ("Env Var",       "WECHAT_APPID=wx_TEST_APP_ID_12345678"),
    ("Private IP",    "Server at 192.168.1.100:8080"),
    ("Phone",         "Call me at 13800138000"),
    ("Mixed",         "Key sk-123456789012345678901234 at D:\config.json IP 10.0.0.5"),
]

print("=" * 60)
print("Single-string sanitization")
print("=" * 60)
for label, text in examples:
    result = sanitize(text)
    changed = result != text
    status = "✅" if changed else "❌"
    print(f"\n{status} [{label}]")
    print(f"   IN:  {text}")
    print(f"  OUT:  {result}")

# --- JSON object ---
data = {
    "chat": "Detroit家人群",
    "messages": [
        {"from": "Alice", "text": "my token is sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456"},
        {"from": "Bob", "text": "try http://192.168.1.100:3000"},
        {"from": "Charlie", "text": "WECHAT_SECRET=TEST_WECHAT_SECRET_1234567890"},
    ]
}

print("\n" + "=" * 60)
print("JSON object sanitization (recursive)")
print("=" * 60)
clean = sanitize_json(data)
import json
print(json.dumps(clean, ensure_ascii=False, indent=2))
