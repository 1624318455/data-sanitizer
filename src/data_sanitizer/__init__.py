# data-sanitizer — Lightweight data sanitization for AI agent pipelines
#
# Strip sensitive data (API keys, tokens, local paths, PII) before
# feeding text to LLMs. Zero external dependencies.

from .core import sanitize, sanitize_json, register_pattern, PATTERNS

__all__ = ["sanitize", "sanitize_json", "register_pattern", "PATTERNS"]
__version__ = "1.0.0"
