import codecs
import json
import subprocess
import sys
import tracemalloc
from dataclasses import dataclass

import pytest

from fast_cipher.tokens import (
    ALPHANUMERIC,
    ALPHANUMERIC_LOWER,
    ALPHANUMERIC_UPPER,
    BASE64,
    BASE64URL,
    DIGITS,
    TokenEncryptor,
)
from fast_cipher.tokens.registry import BUILTIN_PATTERNS
from fast_cipher.tokens.scanner import scan
from fast_cipher.tokens.types import SimpleTokenPattern, StructuredTokenPattern

from .test_tokens import KEY, SAMPLE_TOKENS


def decode_secret(s: str) -> str:
    """Undo the ROT13 that keeps fake credentials away from secret scanners."""
    return codecs.decode(s, "rot13")


@dataclass(frozen=True)
class Fixture:
    name: str
    prefix: str
    token: str

    def span_at(self, start: int) -> str:
        body = self.token[len(self.prefix) :]
        return f"{self.name}@{start}-{start + len(self.token)}:{body}"


AWS_KEY = SAMPLE_TOKENS["aws-access-key"]
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS = Fixture("aws-access-key", "AKIA", AWS_KEY)
SENDGRID = Fixture("sendgrid", "SG.", SAMPLE_TOKENS["sendgrid"])
GITLAB = Fixture("gitlab", "glpat-", decode_secret("tycng-No1-_No1-_No1-_No1-_"))
SLACK_BOT = Fixture("slack-bot", "xoxb-", SAMPLE_TOKENS["slack-bot"])
SLACK_USER = Fixture(
    "slack-user",
    "xoxp-",
    decode_secret("kbkc-123456789012-1234567890123-NOPQRSTUVWXYZABCDEFGHIJKno"),
)
SLACK_USER_THREE_IDS = Fixture(
    "slack-user",
    "xoxp-",
    decode_secret("kbkc-1234567890-9876543210-2468013579-NoPqRsTuVwXyZaBcDeFgHiJk"),
)
SLACK = [SLACK_BOT, SLACK_USER, SLACK_USER_THREE_IDS]

ENCRYPTOR = TokenEncryptor(KEY)


def find(text, patterns=BUILTIN_PATTERNS, all_patterns=None):
    spans = scan(text, patterns, all_patterns)
    return [f"{s.pattern.name}@{s.start}-{s.end}:{s.body}" for s in spans]


def only(name):
    return [p for p in BUILTIN_PATTERNS if p.name == name]


def join(fixtures, separator):
    """Return the tokens joined by `separator`, and the spans scan() should find."""
    spans = []
    start = 0
    for fixture in fixtures:
        spans.append(fixture.span_at(start))
        start += len(fixture.token) + len(separator)
    return separator.join(f.token for f in fixtures), spans


def custom(prefix, body_regex, alphabet, min_body_length, name="custom"):
    return SimpleTokenPattern(name, prefix, body_regex, alphabet, min_body_length)


OVERLONG = "vercel_" + "A" * 20 + AWS_KEY * 40
OUTER = custom("x", "[a-z]{3,}", ALPHANUMERIC_LOWER, 3, name="outer")
INNER = custom("a-", "[0-9]{2}", DIGITS, 2, name="inner")


@pytest.mark.parametrize(
    "patterns,text,expected",
    [
        # Heuristic tokens must be whole words.
        (BUILTIN_PATTERNS, f"_{AWS_SECRET} {AWS_SECRET}_", []),
        # Slack IDs only use ASCII digits.
        (BUILTIN_PATTERNS, "xoxb-" + "\u0663" * 12 + "-1234567890123-abcdefghij", []),
        # The last AWS key ends the Vercel body, even if an earlier one would
        # give a shorter token.
        (
            BUILTIN_PATTERNS,
            OVERLONG,
            [f"vercel@0-807:{OVERLONG[7:807]}", AWS.span_at(807)],
        ),
        # An upper length bound also limits where a body can stop early.
        (
            [custom("tok_", "[A-Za-z0-9]{8,12}", ALPHANUMERIC, 8), *BUILTIN_PATTERNS],
            "tok_" + "a" * 13 + AWS_KEY,
            [AWS.span_at(17)],
        ),
        # A token can start on the last character of another body.
        ([OUTER, INNER], "xbbba-12", ["outer@0-4:bbb", "inner@4-8:12"]),
        (
            [custom("x", "[a-z0-9]{3,}", ALPHANUMERIC_LOWER, 3), INNER],
            "xbbba-12",
            ["custom@0-4:bbb", "inner@4-8:12"],
        ),
        # Stopping early never leaves a body that is empty or too short.
        (
            [custom("hr_", "[ab][a-z0-9]+", ALPHANUMERIC_LOWER, 8), OUTER],
            "hr_abxbbbbbb",
            ["custom@0-12:abxbbbbbb"],
        ),
        (
            [custom("lm_", "[A-Za-z0-9]{2,}", ALPHANUMERIC, 10), *BUILTIN_PATTERNS],
            "lm_abc" + AWS_KEY,
            [f"custom@0-26:abc{AWS_KEY}"],
        ),
        (
            [custom("q:", "[A-Z0-9]{0,3}", ALPHANUMERIC_UPPER, 0), *BUILTIN_PATTERNS],
            "q:" + AWS_KEY,
            [AWS.span_at(2)],
        ),
        # Prefixes can overlap themselves.
        ([custom("aa", "[0-9]{3}", DIGITS, 3)], "aaa123", ["custom@1-6:123"]),
    ],
)
def test_scan(patterns, text, expected):
    assert find(text, patterns) == expected


def test_custom_structured_patterns():
    def whole_body(alphabet):
        return lambda body: {"segments": [body], "alphabets": [alphabet]}

    # An empty match is not a token.
    caps = StructuredTokenPattern(
        "caps",
        "",
        "[A-Z]*",
        ALPHANUMERIC_UPPER,
        whole_body(ALPHANUMERIC_UPPER),
        "".join,
    )
    assert find("ab CD", [caps]) == ["caps@3-5:CD"]


@pytest.mark.parametrize(
    "pattern,valid,invalid",
    [
        (custom("foo_", "[A-Z]{8}", ALPHANUMERIC, 8), "ABCDEFGH", "ABCDEFgH"),
        (custom("key-", "X[A-Z0-9]{7}", ALPHANUMERIC_UPPER, 8), "XABC1234", "YABC1234"),
        (custom("n:", "[1-9]{4}", DIGITS, 4), "2345", "0000"),
        (custom("n:", "[02-9]{4}", DIGITS, 4), "2345", "1111"),
        (custom("n:", "[0-8]{4}", DIGITS, 4), "2345", "9999"),
        (custom("tok_", "[A-Za-z0-9]{8,12}", ALPHANUMERIC, 8), "a" * 12, "a" * 13),
        (custom("neg:", "[^\\s]{10,}", BASE64, 10), "ab+/cd+/ef", "ab+/cd+/e"),
        (
            custom("alt_", "[a-z]{8}|[0-9]{8}", ALPHANUMERIC_LOWER, 8),
            "abcdefgh",
            "abcd1234",
        ),
    ],
    ids=lambda p: getattr(p, "body_regex", None),
)
def test_custom_body_regex(pattern, valid, invalid):
    patterns = [pattern, *BUILTIN_PATTERNS]
    token = pattern.prefix + valid
    span = f"custom@0-{len(token)}:{valid}"
    assert find(token, patterns) == [span]
    assert find(pattern.prefix + invalid, patterns) == []
    assert find(token + AWS_KEY, patterns) == [span, AWS.span_at(len(token))]


@pytest.mark.parametrize("body_regex", ["[A-Za-z0-9_-]{8}", "X[A-Za-z0-9_-]{7}"])
def test_body_keeps_its_own_trailing_dashes(body_regex):
    patterns = [custom("tok:", body_regex, BASE64URL, 8), *BUILTIN_PATTERNS]
    token = "tok:XAAA___-"
    assert find(token + "__--" + AWS_KEY, patterns) == [
        "custom@0-12:XAAA___-",
        AWS.span_at(16),
    ]
    for suffix in ["-", "__--AKIAshort", "A-" + AWS_KEY]:
        spans = find(token + suffix, patterns)
        assert not any(span.startswith("custom@") for span in spans)


SEPARATORS = ["", "-", "_", "-_--"]
NEIGHBORS = [[f] * 4 for f in [SENDGRID, GITLAB, *SLACK]] + [
    [left, right]
    for left in [SENDGRID, GITLAB, SLACK_BOT]
    for right in [SENDGRID, GITLAB, SLACK_BOT]
    if left != right
]


@pytest.mark.parametrize("separator", SEPARATORS, ids=repr)
@pytest.mark.parametrize(
    "fixtures", NEIGHBORS, ids=lambda fs: "+".join(f.name for f in fs)
)
def test_tokens_next_to_each_other(fixtures, separator):
    text, spans = join(fixtures, separator)
    assert find(text) == spans

    first = fixtures[0].name
    expected = [s for f, s in zip(fixtures, spans) if f.name == first]
    assert find(text, only(first), BUILTIN_PATTERNS) == expected

    encrypted, _ = ENCRYPTOR.encrypt(text)
    assert ENCRYPTOR.decrypt(encrypted) == text


@pytest.mark.parametrize("fixture", [SENDGRID, GITLAB], ids=lambda f: f.name)
def test_body_only_stops_early_before_a_valid_token(fixture):
    for suffix in ["Z", "-", f"-{fixture.prefix}short", "AKIA", AWS_KEY + "A"]:
        assert find(fixture.token + suffix) == []

    text, spans = join([fixture, fixture], "Z")
    assert find(text) == spans[1:]


@pytest.mark.parametrize("fixture", SLACK)
def test_slack_tokens_next_to_broken_ones(fixture):
    incomplete = fixture.token + fixture.prefix + "12"
    end = len(fixture.token) + len(fixture.prefix) - 1
    body = incomplete[len(fixture.prefix) : end]
    assert find(incomplete) == [f"{fixture.name}@0-{end}:{body}"]

    broken = "xoxb-1-1-"
    assert find(broken + fixture.token) == [fixture.span_at(len(broken))]


TIMING_SCRIPT = """
import json, sys, time
from fast_cipher.tokens.registry import BUILTIN_PATTERNS
from fast_cipher.tokens.scanner import scan

for name, text in json.load(sys.stdin).items():
    start = time.perf_counter()
    scan(text, BUILTIN_PATTERNS)
    print(json.dumps([name, time.perf_counter() - start]), flush=True)
"""


def test_texts_packed_with_prefixes_scan_quickly():
    # These used to make scanning quadratic or worse.
    size = 200_000
    units = [
        "AKIA",
        AWS_KEY,
        "AIza",
        "pypi-",
        "glc_",
        "glpat-",
        "vercel_",
        "sk-proj-",
        "sk-ant-api03-",
        SLACK_BOT.token,
        SENDGRID.token + "-",
        GITLAB.token + "-",
        "AKIAglc_AIzasbp_pypi-hf_SKnpm_vercel_sk-proj-xoxb-1-1-",
    ]
    texts = {unit: (unit * size)[:size] for unit in units}
    for lead, unit in [
        ("xoxb-1-1-", AWS_KEY),
        ("xoxb-1-1-", "SK" + "a" * 32),
        ("xoxb-1-1-", "AIza"),
        ("xoxp-1-1-1-", "glc_"),
        ("SG.", "AIza"),
    ]:
        texts[lead + unit] = lead + (unit * size)[:size]
    texts["whole AWS keys"] = ("xoxb-1-1-" + AWS_KEY * (size // 20 - 1)).ljust(size)
    texts["long separator"] = GITLAB.token + "-" * size + GITLAB.token

    # A slow scan can't be interrupted, so the scans run in a child process
    # that gets killed if it takes too long.
    try:
        child = subprocess.run(
            [sys.executable, "-c", TIMING_SCRIPT],
            input=json.dumps(texts),
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
    except subprocess.TimeoutExpired as e:
        pytest.fail(f"still scanning after 60 seconds, finished: {e.stdout!r}")
    timings = dict(json.loads(line) for line in child.stdout.splitlines())
    assert {name: t for name, t in timings.items() if t > 1.0} == {}


def test_overlapping_candidates_use_little_memory():
    # Most candidates here overlap and run nearly to the end of the text.
    text = "pypi-" * 4000
    tracemalloc.start()
    try:
        scan(text, BUILTIN_PATTERNS)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 200 * len(text)
