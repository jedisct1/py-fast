from __future__ import annotations

import math
import re
from typing import Callable

from .types import (
    HeuristicTokenPattern,
    SimpleTokenPattern,
    StructuredTokenPattern,
    TokenPattern,
    TokenSpan,
)


def _find_all_positions(text: str, needle: str) -> list[int]:
    positions: list[int] = []
    idx = 0
    while idx <= len(text) - len(needle):
        pos = text.find(needle, idx)
        if pos == -1:
            break
        positions.append(pos)
        idx = pos + 1
    return positions


# Cached compiled regexes
_body_validator_cache: dict[str, re.Pattern[str]] = {}


def _get_body_validator(pattern: SimpleTokenPattern) -> re.Pattern[str]:
    key = pattern.body_regex
    if key not in _body_validator_cache:
        _body_validator_cache[key] = re.compile(f"^(?:{pattern.body_regex})$")
    return _body_validator_cache[key]


def _would_match_at(
    text: str,
    pos: int,
    prefix_positions: set[int],
    all_patterns: list[TokenPattern],
) -> bool:
    for pattern in all_patterns:
        if pattern.kind == "heuristic":
            continue
        if not text[pos:].startswith(pattern.prefix):
            continue
        if pattern.kind == "simple":
            assert isinstance(pattern, SimpleTokenPattern)
            if _would_match_simple_at(
                text, pos, pattern, prefix_positions, all_patterns
            ):
                return True
        else:
            assert isinstance(pattern, StructuredTokenPattern)
            if _would_match_structured_at(
                text, pos, pattern, prefix_positions, all_patterns
            ):
                return True
    return False


def _would_match_simple_at(
    text: str,
    pos: int,
    pattern: SimpleTokenPattern,
    prefix_positions: set[int],
    all_patterns: list[TokenPattern],
) -> bool:
    body_start = pos + len(pattern.prefix)
    body_end = body_start
    while (
        body_end < len(text) and text[body_end] in pattern.body_alphabet.char_to_index
    ):
        body_end += 1

    if body_end - body_start < pattern.min_body_length:
        return False

    validator = _get_body_validator(pattern)

    def validate(body: str) -> bool:
        return (
            len(body) >= pattern.min_body_length and validator.match(body) is not None
        )

    trunc_end = _find_truncated_end(
        text, body_start, body_end, prefix_positions, all_patterns, validate
    )
    if trunc_end != -1:
        return True

    return validate(text[body_start:body_end])


def _would_match_structured_at(
    text: str,
    pos: int,
    pattern: StructuredTokenPattern,
    prefix_positions: set[int],
    all_patterns: list[TokenPattern],
) -> bool:
    regex = re.compile(pattern.full_regex)
    m = regex.match(text, pos)
    if not m:
        return False

    match_end = m.end()
    body_start = pos + len(pattern.prefix)

    trunc_end = _find_truncated_end(
        text,
        body_start,
        match_end,
        prefix_positions,
        all_patterns,
        lambda body: pattern.parse(body) is not None,
    )
    if trunc_end != -1:
        return True

    body = text[body_start:match_end]
    if pattern.parse(body) is not None:
        if match_end < len(text):
            next_ch = text[match_end]
            if next_ch in pattern.trailing_alphabet.char_to_index:
                if match_end not in prefix_positions:
                    return False
        return True

    return False


def _find_truncated_end(
    text: str,
    body_start: int,
    body_end: int,
    prefix_positions: set[int],
    all_patterns: list[TokenPattern],
    validate_left: Callable[[str], bool],
) -> int:
    prefixes_in_body = [
        i for i in range(body_start + 1, body_end) if i in prefix_positions
    ]
    if not prefixes_in_body:
        return -1

    for j in range(len(prefixes_in_body) - 1, -1, -1):
        split_pos = prefixes_in_body[j]
        left_body = text[body_start:split_pos]
        if not validate_left(left_body):
            continue
        if not _would_match_at(text, split_pos, prefix_positions, all_patterns):
            continue
        return split_pos

    return -1


def scan(
    text: str,
    patterns: list[TokenPattern],
    all_patterns: list[TokenPattern] | None = None,
) -> list[TokenSpan]:
    all_pats = all_patterns if all_patterns is not None else patterns
    unique_prefixes = {p.prefix for p in all_pats if p.prefix}

    prefix_positions: set[int] = set()
    for pfx in unique_prefixes:
        for pos in _find_all_positions(text, pfx):
            prefix_positions.add(pos)

    candidates: list[TokenSpan] = []

    for pattern in patterns:
        if pattern.kind == "structured":
            assert isinstance(pattern, StructuredTokenPattern)
            _scan_structured(text, pattern, prefix_positions, all_pats, candidates)
        elif pattern.kind == "heuristic":
            assert isinstance(pattern, HeuristicTokenPattern)
            _scan_heuristic(text, pattern, candidates)
        else:
            assert isinstance(pattern, SimpleTokenPattern)
            _scan_simple(text, pattern, prefix_positions, all_pats, candidates)

    # Sort: position -> longest prefix -> longest match
    candidates.sort(key=lambda s: (s.start, -len(s.pattern.prefix), -(s.end - s.start)))

    # Remove overlaps
    result: list[TokenSpan] = []
    last_end = 0
    for span in candidates:
        if span.start >= last_end:
            result.append(span)
            last_end = span.end

    return result


def _scan_simple(
    text: str,
    pattern: SimpleTokenPattern,
    prefix_positions: set[int],
    all_patterns: list[TokenPattern],
    candidates: list[TokenSpan],
) -> None:
    validator = _get_body_validator(pattern)

    def validate(body: str) -> bool:
        return (
            len(body) >= pattern.min_body_length and validator.match(body) is not None
        )

    for pos in _find_all_positions(text, pattern.prefix):
        if not _is_word_boundary(text, pos):
            continue

        body_start = pos + len(pattern.prefix)
        body_end = body_start
        while (
            body_end < len(text)
            and text[body_end] in pattern.body_alphabet.char_to_index
        ):
            body_end += 1

        if body_end - body_start < pattern.min_body_length:
            continue

        trunc_end = _find_truncated_end(
            text, body_start, body_end, prefix_positions, all_patterns, validate
        )

        if trunc_end != -1:
            final_end = trunc_end
        else:
            full_body = text[body_start:body_end]
            if not validate(full_body):
                continue
            final_end = body_end

        candidates.append(
            TokenSpan(
                start=pos,
                end=final_end,
                pattern=pattern,
                body=text[body_start:final_end],
            )
        )


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _count_char_classes(s: str) -> int:
    has_upper = has_lower = has_digit = has_other = False
    for c in s:
        code = ord(c)
        if 65 <= code <= 90:
            has_upper = True
        elif 97 <= code <= 122:
            has_lower = True
        elif 48 <= code <= 57:
            has_digit = True
        else:
            has_other = True
    return sum([has_upper, has_lower, has_digit, has_other])


_WORD_BOUNDARY_RE = re.compile(r"[^A-Za-z0-9_-]")


def _is_word_boundary(text: str, pos: int) -> bool:
    if pos == 0:
        return True
    return _WORD_BOUNDARY_RE.match(text[pos - 1]) is not None


def _is_word_boundary_end(text: str, pos: int) -> bool:
    if pos >= len(text):
        return True
    return _WORD_BOUNDARY_RE.match(text[pos]) is not None


def _scan_heuristic(
    text: str,
    pattern: HeuristicTokenPattern,
    candidates: list[TokenSpan],
) -> None:
    i = 0
    while i < len(text):
        if text[i] not in pattern.body_alphabet.char_to_index:
            i += 1
            continue

        if not _is_word_boundary(text, i):
            while i < len(text) and text[i] in pattern.body_alphabet.char_to_index:
                i += 1
            continue

        end = i
        while end < len(text) and text[end] in pattern.body_alphabet.char_to_index:
            end += 1

        length = end - i
        if (
            length >= pattern.min_length
            and length <= pattern.max_length
            and _is_word_boundary_end(text, end)
        ):
            body = text[i:end]
            if (
                _count_char_classes(body) >= pattern.min_char_classes
                and shannon_entropy(body) >= pattern.min_entropy
            ):
                candidates.append(
                    TokenSpan(
                        start=i,
                        end=end,
                        pattern=pattern,
                        body=body,
                    )
                )

        i = end


def _scan_structured(
    text: str,
    pattern: StructuredTokenPattern,
    prefix_positions: set[int],
    all_patterns: list[TokenPattern],
    candidates: list[TokenSpan],
) -> None:
    regex = re.compile(pattern.full_regex)
    for m in regex.finditer(text):
        match_start = m.start()
        if not _is_word_boundary(text, match_start):
            continue
        match_end = m.end()
        body_start = match_start + len(pattern.prefix)

        trunc_end = _find_truncated_end(
            text,
            body_start,
            match_end,
            prefix_positions,
            all_patterns,
            lambda body: pattern.parse(body) is not None,
        )

        if trunc_end != -1:
            candidates.append(
                TokenSpan(
                    start=match_start,
                    end=trunc_end,
                    pattern=pattern,
                    body=text[body_start:trunc_end],
                )
            )
            continue

        # No truncation - apply trailing boundary check
        if match_end < len(text):
            next_ch = text[match_end]
            if next_ch in pattern.trailing_alphabet.char_to_index:
                if match_end not in prefix_positions:
                    continue

        candidates.append(
            TokenSpan(
                start=match_start,
                end=match_end,
                pattern=pattern,
                body=text[body_start:match_end],
            )
        )
