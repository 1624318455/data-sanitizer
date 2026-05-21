#!/usr/bin/env python3
"""Command-line interface for data-sanitizer.

Usage:
    data-sanitizer --input messages.json --output clean.json
    cat data.json | data-sanitizer --input - > clean.json
    data-sanitizer --list
    data-sanitizer --no-json --input raw.log --output clean.log
"""

import argparse
import json
import sys

from .core import PATTERNS, sanitize, sanitize_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="data-sanitizer — strip sensitive data before LLM processing",
    )
    parser.add_argument(
        "--input", "-i", default="-",
        help="Input file path (default: stdin, use '-' explicitly for pipe)",
    )
    parser.add_argument(
        "--output", "-o", default="-",
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--no-json", action="store_true",
        help="Treat input as plain text (default: auto-detect JSON)",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List all registered redaction patterns and exit",
    )
    return parser


def list_patterns() -> None:
    """Print the pattern table to stdout."""
    width = 60
    print("=" * width)
    print(f"{'Label':<20} Pattern")
    print("=" * width)
    for label, regex in PATTERNS:
        print(f"{label:<20} {regex}")
    print("=" * width)
    print(f"Total: {len(PATTERNS)} pattern(s)")


def read_input(path: str) -> str:
    """Read text from a file or stdin."""
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def write_output(path: str, content: str) -> None:
    """Write text to a file or stdout."""
    if path == "-":
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # --- List mode ---
    if args.list:
        list_patterns()
        sys.exit(0)

    # --- Read ---
    raw = read_input(args.input)

    # --- Sanitize ---
    if args.no_json:
        result = sanitize(raw)
    else:
        try:
            data = json.loads(raw)
            result = json.dumps(sanitize_json(data), ensure_ascii=False, indent=2)
        except json.JSONDecodeError:
            # Fallback: treat as plain text
            result = sanitize(raw)

    # --- Write ---
    write_output(args.output, result)


if __name__ == "__main__":
    main()
