# Data Sanitizer 🧹🔐

Strip sensitive data (API keys, tokens, local paths, PII) before feeding text to LLMs. Zero external dependencies — pure regex, runs anywhere.

## Why

Every AI agent pipeline faces the same problem: **your chat messages, logs, and configs contain secrets.** API keys (`sk-...`), GitHub tokens (`ghp_...`), JWT tokens, local file paths (`D:\Work\...`), environment variable values, private IPs, phone numbers — all of these can leak into LLM output if you're not careful.

Existing PII tools (Presidio, scrubadub) are either too heavy or don't cover the patterns AI agent users actually need.

**data-sanitizer** fills the gap: a lightweight, zero-dependency Python package that catches what matters for AI agent pipelines.

## Installation

```bash
pip install data-sanitizer
```

Or install from source:

```bash
git clone https://github.com/1624318455/data-sanitizer.git
cd data-sanitizer
pip install -e .
```

## Quick Start

```python
from data_sanitizer import sanitize

text = "My API key is sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456"
print(sanitize(text))
# → "My API key is [API_KEY_REDACTED]"
```

## CLI Usage

```bash
# Sanitize a JSON file (recursively cleans all string fields)
data-sanitizer --input messages.json --output clean.json

# Pipe from stdin
cat messages.json | data-sanitizer --input - > clean.json

# Plain text mode
data-sanitizer --no-json --input raw.log --output clean.log

# List all available redaction patterns
data-sanitizer --list
```

## Patterns

| Category | Pattern | Example | Replaced By |
|----------|---------|---------|-------------|
| OpenAI / Generic API Key | `sk-[A-Za-z0-9_-]{20,}` | `sk-proj-AbCd...` | `[API_KEY_REDACTED]` |
| GitHub Token | `gh[pousr]_[A-Za-z0-9_-]{20,}` | `ghp_abc...` | `[GITHUB_TOKEN_REDACTED]` |
| Slack Token | `xox[abpst]-[A-Za-z0-9_-]{10,}` | `xoxb-123...` | `[SLACK_TOKEN_REDACTED]` |
| JWT / Bearer Token | `eyJ...` three-part base64 | `eyJhbGci...` | `[JWT_REDACTED]` |
| Local Path (Windows) | `X:\...` | `D:\Work\ForAI\` | `[LOCAL_PATH_REDACTED]` |
| Env Var Value Leak | Known keys + value | `WECHAT_APPID=xxx` | `[ENV_VAL_REDACTED]` |
| Private IP | `10.x.x.x`, `192.168.x.x`, `172.16-31.x.x` | `192.168.1.100` | `[PRIVATE_IP_REDACTED]` |
| Phone (China) | `1[3-9]\d{9}` | `13800138000` | `[PHONE_CN_REDACTED]` |

## Integration

### In Hermes Agent

```bash
skill_view(name='data-sanitizer')
# Then in your workflow:
terminal(f'''python -m data_sanitizer \\
  --input /tmp/raw.json \\
  --output /tmp/clean.json''')
```

### In any Python script

```python
from data_sanitizer import sanitize, sanitize_json

# Single string
clean = sanitize("sk-xxx")

# JSON object
clean_obj = sanitize_json(raw_data)
```

## Customization

Pass custom patterns via environment variable:

```bash
export DATA_SANITIZER_PATTERNS=/path/to/patterns.yaml
```

Or extend in code:

```python
from data_sanitizer import sanitize, register_pattern

register_pattern("SSH_KEY", r"-----BEGIN OPENSSH PRIVATE KEY-----")
clean = sanitize(text)
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
