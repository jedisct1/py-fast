from __future__ import annotations

import re

from .alphabets import (
    ALPHANUMERIC,
    ALPHANUMERIC_LOWER,
    ALPHANUMERIC_UPPER,
    BASE64,
    BASE64URL,
    DIGITS,
    HEX_LOWER,
    Alphabet,
)
from .types import (
    HeuristicTokenPattern,
    SimpleTokenPattern,
    StructuredTokenPattern,
    TokenPattern,
)

MIN_SEGMENT_LENGTH = 4


def _simple(
    name: str,
    prefix: str,
    body_regex: str,
    body_alphabet: Alphabet,
    min_body_length: int,
) -> SimpleTokenPattern:
    return SimpleTokenPattern(
        name=name,
        prefix=prefix,
        body_regex=body_regex,
        body_alphabet=body_alphabet,
        min_body_length=min_body_length,
    )


def _heuristic(
    name: str,
    body_alphabet: Alphabet,
    min_length: int,
    max_length: int,
    min_entropy: float,
    min_char_classes: int,
) -> HeuristicTokenPattern:
    return HeuristicTokenPattern(
        name=name,
        body_alphabet=body_alphabet,
        min_length=min_length,
        max_length=max_length,
        min_entropy=min_entropy,
        min_char_classes=min_char_classes,
    )


def _make_slack_pattern(prefix: str, name: str) -> StructuredTokenPattern:
    escaped = re.escape(prefix)

    def parse(body: str) -> dict | None:
        parts = body.split("-")
        if len(parts) < 3:
            return None
        total_len = sum(len(p) for p in parts)
        if total_len < 20:
            return None
        alphabets: list[Alphabet] = []
        for part in parts:
            if re.fullmatch(r"\d+", part):
                alphabets.append(DIGITS)
            elif re.fullmatch(r"[A-Za-z0-9]+", part):
                alphabets.append(ALPHANUMERIC)
            else:
                return None
        return {"segments": parts, "alphabets": alphabets}

    def format_fn(segments: list[str]) -> str:
        return "-".join(segments)

    return StructuredTokenPattern(
        name=name,
        prefix=prefix,
        full_regex=f"{escaped}\\d+-\\d+-[A-Za-z0-9]+",
        trailing_alphabet=ALPHANUMERIC,
        parse=parse,
        format=format_fn,
    )


def _make_sendgrid_parse(body: str) -> dict | None:
    dot_idx = body.find(".")
    if dot_idx == -1:
        return None
    seg1 = body[:dot_idx]
    seg2 = body[dot_idx + 1 :]
    if len(seg1) != 22 or len(seg2) != 43:
        return None
    return {"segments": [seg1, seg2], "alphabets": [BASE64URL, BASE64URL]}


def _make_sendgrid_format(segments: list[str]) -> str:
    return f"{segments[0]}.{segments[1]}"


_sendgrid_pattern = StructuredTokenPattern(
    name="sendgrid",
    prefix="SG.",
    full_regex=r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    trailing_alphabet=BASE64URL,
    parse=_make_sendgrid_parse,
    format=_make_sendgrid_format,
)


# Ordered by longest prefix first for correct overlap resolution
BUILTIN_PATTERNS: list[TokenPattern] = [
    # Anthropic (13-char prefix)
    _simple("anthropic", "sk-ant-api03-", "[A-Za-z0-9_-]{80,}", BASE64URL, 80),
    # OpenAI sk-proj- (8-char prefix)
    _simple("openai", "sk-proj-", "[A-Za-z0-9_-]{48,}", BASE64URL, 48),
    _simple("openai-legacy", "sk-", "[A-Za-z0-9]{48}", ALPHANUMERIC, 48),
    # Stripe (8-char prefix)
    _simple("stripe-secret-live", "sk_live_", "[A-Za-z0-9]{24,}", ALPHANUMERIC, 24),
    _simple("stripe-publish-live", "pk_live_", "[A-Za-z0-9]{24,}", ALPHANUMERIC, 24),
    _simple("stripe-secret-test", "sk_test_", "[A-Za-z0-9]{24,}", ALPHANUMERIC, 24),
    _simple("stripe-publish-test", "pk_test_", "[A-Za-z0-9]{24,}", ALPHANUMERIC, 24),
    # Vercel (7-char prefix)
    _simple("vercel", "vercel_", "[A-Za-z0-9_-]{20,}", BASE64URL, 20),
    # GitLab (6-char prefix)
    _simple("gitlab", "glpat-", "[A-Za-z0-9_-]{20}", BASE64URL, 20),
    # Datadog (6-char prefix)
    _simple("datadog", "ddapi_", "[a-z0-9]{40}", ALPHANUMERIC_LOWER, 40),
    # PyPI (5-char prefix)
    _simple("pypi", "pypi-", "[A-Za-z0-9_-]{50,}", BASE64URL, 50),
    # Slack (5-char prefix, structured)
    _make_slack_pattern("xoxb-", "slack-bot"),
    _make_slack_pattern("xoxp-", "slack-user"),
    # GitHub (4-char prefix)
    _simple("github-pat", "ghp_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
    _simple("github-oauth", "gho_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
    _simple("github-user", "ghu_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
    _simple("github-server", "ghs_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
    _simple("github-refresh", "ghr_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
    # AWS (4-char prefix)
    _simple("aws-access-key", "AKIA", "[A-Z0-9]{16}", ALPHANUMERIC_UPPER, 16),
    # Google (4-char prefix)
    _simple("google-api", "AIza", "[A-Za-z0-9_-]{35}", BASE64URL, 35),
    # npm (4-char prefix)
    _simple("npm", "npm_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
    # Supabase (4-char prefix)
    _simple("supabase", "sbp_", "[a-f0-9]{40}", HEX_LOWER, 40),
    # Grafana (4-char prefix)
    _simple("grafana", "glc_", "[A-Za-z0-9_-]{30,}", BASE64URL, 30),
    # HuggingFace (3-char prefix)
    _simple("huggingface", "hf_", "[A-Za-z0-9]{34}", ALPHANUMERIC, 34),
    # SendGrid (3-char prefix, structured)
    _sendgrid_pattern,
    # Twilio (2-char prefix)
    _simple("twilio", "SK", "[a-f0-9]{32}", HEX_LOWER, 32),
    # Heuristic patterns (no prefix, entropy-based)
    _heuristic("fastly", BASE64URL, 32, 32, 4.0, 3),
    _heuristic("aws-secret-key", BASE64, 40, 40, 4.0, 3),
]
