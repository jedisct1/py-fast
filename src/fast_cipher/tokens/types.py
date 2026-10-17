from __future__ import annotations

import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from .alphabets import Alphabet

_CHARACTER_CLASS_WITH_LENGTH = re.compile(
    r"(\[(?:[^\\\[\]]|\\.)+\])\{([0-9]{1,9})(?:(,)([0-9]{0,9}))?\}"
)


def _compile(regex: str) -> re.Pattern[str]:
    # As in JavaScript, \d and \w only match ASCII characters.
    return re.compile(regex, re.ASCII)


def _length_bounds(
    body_regex: str, alphabet: Alphabet, min_body_length: int
) -> tuple[int, int] | None:
    """Return the allowed body lengths when that is all `body_regex` checks.

    That's the case for a single character class with a length, such as
    [A-Za-z0-9]{32}, when the class accepts the whole alphabet.

    The scanner then only checks lengths, which keeps it fast.
    """
    m = _CHARACTER_CLASS_WITH_LENGTH.fullmatch(body_regex)
    if m is None:
        return None
    char_class = _compile(m[1])
    if not all(char_class.fullmatch(ch) for ch in alphabet.chars):
        return None
    low = int(m[2])
    high = low
    if m[3]:
        high = int(m[4]) if m[4] else sys.maxsize
    return max(low, min_body_length), high


@dataclass(frozen=True)
class SimpleTokenPattern:
    kind: Literal["simple"] = field(default="simple", init=False)
    name: str
    prefix: str
    body_regex: str
    body_alphabet: Alphabet
    min_body_length: int
    _body_validator: re.Pattern[str] = field(init=False, repr=False, compare=False)
    _length_bounds: tuple[int, int] | None = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "_body_validator", _compile(self.body_regex))
        object.__setattr__(
            self,
            "_length_bounds",
            _length_bounds(self.body_regex, self.body_alphabet, self.min_body_length),
        )


@dataclass(frozen=True)
class StructuredTokenPattern:
    """A token whose body is made of segments, each with its own alphabet.

    `parse` splits a body into segments and alphabets, or returns None when
    the body is invalid.

    It can be called several times on the same body, so it must always give
    the same answer.
    """

    kind: Literal["structured"] = field(default="structured", init=False)
    name: str
    prefix: str
    full_regex: str
    trailing_alphabet: Alphabet
    parse: Callable[[str], dict | None]
    format: Callable[[list[str]], str]
    _regex: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_regex", _compile(self.full_regex))


@dataclass(frozen=True)
class HeuristicTokenPattern:
    kind: Literal["heuristic"] = field(default="heuristic", init=False)
    name: str
    prefix: str = ""
    body_alphabet: Alphabet = field(default=None)  # type: ignore
    min_length: int = 0
    max_length: int = 0
    min_entropy: float = 0.0
    min_char_classes: int = 0


TokenPattern = SimpleTokenPattern | StructuredTokenPattern | HeuristicTokenPattern


@dataclass
class TokenSpan:
    start: int
    end: int
    pattern: TokenPattern
    body: str


@dataclass(frozen=True)
class TokenMapping:
    """A single plaintext-to-ciphertext token mapping produced by encrypt()."""

    plaintext: str
    ciphertext: str
    pattern_name: str
