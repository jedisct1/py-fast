from __future__ import annotations

import math
import re
import string
from bisect import bisect_right
from functools import lru_cache
from typing import Callable

from .alphabets import Alphabet
from .types import (
    HeuristicTokenPattern,
    SimpleTokenPattern,
    StructuredTokenPattern,
    TokenPattern,
    TokenSpan,
)

_PrefixedPattern = SimpleTokenPattern | StructuredTokenPattern
_Candidate = tuple[int, int, TokenPattern]

_SEPARATORS = "-_"
_WORD_CHARS = frozenset(string.ascii_letters + string.digits + _SEPARATORS)
_NEVER = re.compile("(?!)")


def _find_all_positions(text: str, needle: str) -> list[int]:
    positions: list[int] = []
    pos = text.find(needle)
    while pos != -1:
        positions.append(pos)
        pos = text.find(needle, pos + 1)
    return positions


def _char_class(chars) -> str:
    return "[" + "".join(re.escape(ch) for ch in chars) + "]"


@lru_cache(maxsize=256)
def _alphabet_runs(chars: str) -> re.Pattern[str]:
    if not chars:
        return _NEVER
    return re.compile(_char_class(chars) + "+")


@lru_cache(maxsize=256)
def _heuristic_words(chars: str, min_length: int) -> re.Pattern[str]:
    """Match whole words made of `chars`, at least `min_length` long.

    Most words are shorter, and skipping them here is much faster.
    """
    if not chars:
        return _NEVER
    neighbor = _char_class(set(chars) | _WORD_CHARS)
    body = _char_class(chars) + "{%d,}" % max(min_length, 1)
    return re.compile(f"(?<!{neighbor}){body}(?!{neighbor})")


class _RunEnds:
    """Find where runs of alphabet characters end.

    The last run is remembered, so going through positions in one direction
    reads each character only once.
    """

    __slots__ = ("_text", "_runs", "_start", "_end")

    def __init__(self, text: str, alphabet: Alphabet) -> None:
        self._text = text
        self._runs = _alphabet_runs(alphabet.chars)
        self._start = -1
        self._end = -2

    def from_pos(self, pos: int) -> int:
        if self._start <= pos <= self._end:
            return self._end
        # If this run reaches the previous one, it ends where that one did.
        limit = self._start if pos < self._start else len(self._text)
        m = self._runs.match(self._text, pos, limit)
        end = m.end() if m else pos
        if end == self._start:
            end = self._end
        self._start = pos
        self._end = end
        return end


_PatternRuns = tuple[_PrefixedPattern, _RunEnds | None]


class _Boundaries:
    """Where token bodies can stop early in one text.

    A body can stop where another token starts, or on the dashes and
    underscores right before it.

    Whether a token starts somewhere only depends on the text after it.
    So prefix positions are checked once, from the end of the text backward,
    and each check can reuse what was found after it.
    """

    def __init__(self, text: str, all_patterns: list[TokenPattern]) -> None:
        self._text = text
        self._occurrences: dict[str, list[int]] = {}
        found: set[int] = set()
        for pattern in all_patterns:
            prefix = pattern.prefix
            if not prefix or prefix in self._occurrences:
                continue
            occurrences = _find_all_positions(text, prefix)
            self._occurrences[prefix] = occurrences
            found.update(occurrences)

        # Filled from the back, only _ends[_first:] is in use.
        self._ends: list[int] = []
        self._first = 0
        if not found:
            return
        separators = sum(text.count(sep) for sep in _SEPARATORS)
        self._ends = [0] * (len(found) + separators)
        self._first = len(self._ends)
        self._find_ends(sorted(found), all_patterns)

    def _find_ends(
        self, positions: list[int], all_patterns: list[TokenPattern]
    ) -> None:
        text = self._text
        by_first_char: dict[str, list[_PatternRuns]] = {}
        unprefixed: list[_PatternRuns] = []
        for pattern in all_patterns:
            if pattern.kind == "heuristic" or (
                pattern.prefix and not self._occurrences[pattern.prefix]
            ):
                continue
            runs = (
                _RunEnds(text, pattern.body_alphabet)
                if pattern.kind == "simple"
                else None
            )
            if pattern.prefix:
                by_first_char.setdefault(pattern.prefix[0], []).append((pattern, runs))
            else:
                unprefixed.append((pattern, runs))

        ends = self._ends
        lowest_end = len(text) + 1
        for pos in reversed(positions):
            # Already an end, in the separators before a later token.
            if pos >= lowest_end:
                continue
            group = by_first_char.get(text[pos], ())
            if self._token_starts_at(pos, group) or self._token_starts_at(
                pos, unprefixed
            ):
                lowest_end = pos
                while lowest_end > 0 and text[lowest_end - 1] in _SEPARATORS:
                    lowest_end -= 1
                first = self._first - (pos - lowest_end + 1)
                ends[first : self._first] = range(lowest_end, pos + 1)
                self._first = first

    def _token_starts_at(self, pos: int, patterns: list[_PatternRuns]) -> bool:
        for pattern, runs in patterns:
            if not self._text.startswith(pattern.prefix, pos):
                continue
            if pattern.kind == "simple":
                end = self.simple_end(pattern, pos, runs)
            else:
                end = self.structured_end_at(pattern, pos)
            if end != -1:
                return True
        return False

    def occurrences_of(self, prefix: str) -> list[int]:
        occurrences = self._occurrences.get(prefix)
        if occurrences is None:
            return _find_all_positions(self._text, prefix)
        return occurrences

    def simple_end(self, pattern: SimpleTokenPattern, pos: int, runs: _RunEnds) -> int:
        """Return where a simple token starting at `pos` ends, or -1.

        The body stops before the furthest token that leaves it valid.
        If there is none, it takes its whole alphabet run.
        """
        body_start = pos + len(pattern.prefix)
        body_end = runs.from_pos(body_start)
        if body_end - body_start < pattern.min_body_length:
            return -1

        bounds = pattern._length_bounds
        if bounds is not None:
            low, high = bounds
            ends, first = self._ends, self._first
            k = bisect_right(ends, min(body_end, body_start + high), first) - 1
            if k >= first and ends[k] >= body_start + max(low, 1):
                return ends[k]
            return body_end if low <= body_end - body_start <= high else -1

        validator = pattern._body_validator
        min_length = pattern.min_body_length

        def validate(body: str) -> bool:
            return len(body) >= min_length and validator.fullmatch(body) is not None

        split = self._split(body_start, body_end, validate)
        if split != -1:
            return split
        return body_end if validate(self._text[body_start:body_end]) else -1

    def structured_end_at(self, pattern: StructuredTokenPattern, pos: int) -> int:
        """Return where a structured token starting at `pos` ends, or -1."""
        m = pattern._regex.match(self._text, pos)
        if m is None:
            return -1
        match_end = m.end()
        text = self._text
        body_start = pos + len(pattern.prefix)
        parse = pattern.parse

        def validate(body: str) -> bool:
            return parse(body) is not None

        split = self._split(body_start, match_end, validate)
        if split != -1:
            return split
        if not validate(text[body_start:match_end]):
            return -1
        if (
            match_end < len(text)
            and text[match_end] in pattern.trailing_alphabet.char_to_index
            and not self._is_boundary_position(match_end)
        ):
            return -1
        return match_end

    def _split(
        self, body_start: int, body_end: int, validate_left: Callable[[str], bool]
    ) -> int:
        """Return the furthest place before a token where the body is valid, or -1."""
        ends, first = self._ends, self._first
        for k in range(bisect_right(ends, body_end, first) - 1, first - 1, -1):
            end = ends[k]
            if end <= body_start:
                break
            if validate_left(self._text[body_start:end]):
                return end
        return -1

    def _is_boundary_position(self, pos: int) -> bool:
        k = bisect_right(self._ends, pos, self._first) - 1
        return k >= self._first and self._ends[k] == pos


def scan(
    text: str,
    patterns: list[TokenPattern],
    all_patterns: list[TokenPattern] | None = None,
) -> list[TokenSpan]:
    """Find non-overlapping tokens in `text`.

    Tokens matching `all_patterns` can end the body of the token before them,
    even when they are not returned.
    """
    boundaries = _Boundaries(
        text, all_patterns if all_patterns is not None else patterns
    )
    candidates: list[_Candidate] = []

    for pattern in patterns:
        if pattern.kind == "structured":
            _scan_structured(pattern, boundaries, candidates)
        elif pattern.kind == "heuristic":
            _scan_heuristic(text, pattern, candidates)
        else:
            _scan_simple(text, pattern, boundaries, candidates)

    # Prefer earlier matches, then longer prefixes and longer matches.
    candidates.sort(key=lambda c: (c[0], -len(c[2].prefix), c[0] - c[1]))

    # Candidates can overlap a lot, so only copy the bodies we keep.
    result: list[TokenSpan] = []
    last_end = 0
    for start, end, pattern in candidates:
        if start >= last_end:
            body = text[start + len(pattern.prefix) : end]
            result.append(TokenSpan(start, end, pattern, body))
            last_end = end

    return result


def _scan_simple(
    text: str,
    pattern: SimpleTokenPattern,
    boundaries: _Boundaries,
    candidates: list[_Candidate],
) -> None:
    positions = boundaries.occurrences_of(pattern.prefix)
    if not positions:
        return
    runs = _RunEnds(text, pattern.body_alphabet)
    for pos in positions:
        end = boundaries.simple_end(pattern, pos, runs)
        if end != -1:
            candidates.append((pos, end, pattern))


def _scan_structured(
    pattern: StructuredTokenPattern,
    boundaries: _Boundaries,
    candidates: list[_Candidate],
) -> None:
    for start in boundaries.occurrences_of(pattern.prefix):
        end = boundaries.structured_end_at(pattern, start)
        if end != -1 and end != start:
            candidates.append((start, end, pattern))


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
        if "A" <= c <= "Z":
            has_upper = True
        elif "a" <= c <= "z":
            has_lower = True
        elif "0" <= c <= "9":
            has_digit = True
        else:
            has_other = True
    return has_upper + has_lower + has_digit + has_other


def _scan_heuristic(
    text: str,
    pattern: HeuristicTokenPattern,
    candidates: list[_Candidate],
) -> None:
    words = _heuristic_words(pattern.body_alphabet.chars, pattern.min_length)
    for m in words.finditer(text):
        body = m.group()
        if (
            len(body) <= pattern.max_length
            and _count_char_classes(body) >= pattern.min_char_classes
            and shannon_entropy(body) >= pattern.min_entropy
        ):
            candidates.append((m.start(), m.end(), pattern))
