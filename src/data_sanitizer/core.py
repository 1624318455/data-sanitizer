#!/usr/bin/env python3
"""Core sanitization logic — zero external dependencies.

Provides:
    sanitize(text)        → sanitized text
    sanitize_json(obj)    → recursively sanitized JSON-like object
    register_pattern()    → add custom patterns at runtime
    PATTERNS              → default pattern list (list of (label, regex))
"""

import re
from copy import deepcopy

# ============================================================
# Default redaction patterns (priority-ordered)
# ============================================================

_DEFAULT_PATTERNS = [
    # --- API Keys / Tokens ---
    ("API_KEY",       r'(?<![A-Za-z0-9])(sk-[A-Za-z0-9_-]{20,})(?![A-Za-z0-9])'),
    ("GITHUB_TOKEN",  r'(?<![A-Za-z0-9])(gh[pousr]_[A-Za-z0-9_-]{20,})(?![A-Za-z0-9])'),
    ("SLACK_TOKEN",   r'(?<![A-Za-z0-9])(xox[abpst]-[A-Za-z0-9_-]{10,})(?![A-Za-z0-9])'),
    ("JWT",           r'(?<![A-Za-z0-9])(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})(?![A-Za-z0-9])'),

    # --- Local paths (Windows) ---
    ("LOCAL_PATH",    r'(?<![A-Za-z0-9])([A-Za-z]:\\(?:[^\s:,;"\')]+[\\/]?)+)(?![A-Za-z0-9])'),

    # --- Environment variable value leaks ---
    ("ENV_VAL",       r'(?:WECHAT_APPID|WECHAT_SECRET|APP_SECRET|API_KEY|ACCESS_KEY|SECRET_KEY|APP_ID|APP_KEY)[=:]["\']?([A-Za-z0-9_-]{8,})["\']?'),

    # --- Private IP addresses ---
    ("PRIVATE_IP",    r'(?<![A-Za-z0-9])((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:192\.168\.\d{1,3}\.\d{1,3})|(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}))(?![A-Za-z0-9])'),

    # --- Chinese mobile phone numbers ---
    ("PHONE_CN",      r'(?<![A-Za-z0-9])1[3-9]\d{9}(?![A-Za-z0-9])'),
]

# Mutable copy so register_pattern() can modify
PATTERNS = deepcopy(_DEFAULT_PATTERNS)


def register_pattern(label: str, pattern: str, index: int | None = None) -> None:
    """Register a custom redaction pattern at runtime.

    Args:
        label: Short identifier, becomes [LABEL_REDACTED] in output.
        pattern: Regex string to match.
        index: Insert position (None = append to end).
    """
    entry = (label, pattern)
    if index is None:
        PATTERNS.append(entry)
    else:
        PATTERNS.insert(index, entry)


def reset_patterns() -> None:
    """Reset PATTERNS to the built-in defaults."""
    global PATTERNS  # noqa: PLW0603
    PATTERNS.clear()
    PATTERNS.extend(deepcopy(_DEFAULT_PATTERNS))


def sanitize(text: str) -> str:
    """Redact sensitive information from a text string.

    Args:
        text: Raw input string.

    Returns:
        String with sensitive patterns replaced by [LABEL_REDACTED] markers.
    """
    if not isinstance(text, str):
        return text

    for label, pattern in PATTERNS:
        text = re.sub(pattern, f'[{label}_REDACTED]', text)
    return text


def sanitize_json(obj):
    """Recursively sanitize all string values in a JSON-like object.

    Handles nested dicts, lists, and primitive types.  Non-string values
    (int, float, bool, None) are returned unchanged.

    Args:
        obj: A JSON-deserialized Python object (dict, list, str, etc.).

    Returns:
        Sanitized copy of the input object.
    """
    if isinstance(obj, str):
        return sanitize(obj)
    if isinstance(obj, dict):
        return {k: sanitize_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_json(item) for item in obj]
    return obj
