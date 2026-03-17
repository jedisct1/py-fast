from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Literal

from .alphabets import Alphabet


@dataclass(frozen=True)
class SimpleTokenPattern:
    kind: Literal["simple"] = field(default="simple", init=False)
    name: str
    prefix: str
    body_regex: str
    body_alphabet: Alphabet
    min_body_length: int


@dataclass(frozen=True)
class StructuredTokenPattern:
    kind: Literal["structured"] = field(default="structured", init=False)
    name: str
    prefix: str
    full_regex: str
    trailing_alphabet: Alphabet
    parse: Callable[[str], dict | None]
    format: Callable[[list[str]], str]


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
