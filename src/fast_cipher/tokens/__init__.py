from __future__ import annotations

from typing import Any

from ..cipher import FastCipher
from ..params import calculate_recommended_params
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
from .registry import BUILTIN_PATTERNS, MIN_SEGMENT_LENGTH
from .scanner import scan
from .transformer import transform_body
from .types import HeuristicTokenPattern, TokenPattern, TokenSpan


def _heuristic_marker(pattern_name: str) -> str:
    return f"[ENCRYPTED:{pattern_name}]"


def _make_tweak(pattern_name: str, extra: bytes | None = None) -> bytes:
    name_bytes = pattern_name.encode("utf-8")
    if not extra:
        return name_bytes
    return name_bytes + b"\x00" + extra


class TokenEncryptor:
    """Format-preserving encryption for API tokens and secrets."""

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24, or 32 bytes")
        self._key = bytes(key)
        self._cache: dict[tuple[int, int], FastCipher] = {}
        self._patterns: list[TokenPattern] = list(BUILTIN_PATTERNS)
        self._destroyed = False

    def _assert_alive(self) -> None:
        if self._destroyed:
            raise RuntimeError("TokenEncryptor has been destroyed")

    def _get_cipher(self, radix: int, word_length: int) -> FastCipher:
        k = (radix, word_length)
        cipher = self._cache.get(k)
        if cipher is None:
            params = calculate_recommended_params(radix, word_length)
            cipher = FastCipher(params, self._key)
            self._cache[k] = cipher
        return cipher

    def _active_patterns(self, types: list[str] | None = None) -> list[TokenPattern]:
        if not types:
            return self._patterns
        allowed = set(types)
        return [p for p in self._patterns if p.name in allowed]

    def encrypt(
        self,
        text: str,
        *,
        types: list[str] | None = None,
        tweak: bytes | None = None,
    ) -> str:
        self._assert_alive()
        patterns = self._active_patterns(types)
        spans = scan(text, patterns, self._patterns)
        if not spans:
            return text

        parts: list[str] = []
        cursor = 0
        for span in spans:
            parts.append(text[cursor : span.start])
            parts.append(self._transform_span(span, tweak, "encrypt"))
            cursor = span.end
        parts.append(text[cursor:])
        return "".join(parts)

    def decrypt(
        self,
        text: str,
        *,
        types: list[str] | None = None,
        tweak: bytes | None = None,
    ) -> str:
        self._assert_alive()
        patterns = self._active_patterns(types)

        # First pass: decrypt heuristic markers
        heuristic_patterns = [p for p in patterns if p.kind == "heuristic"]
        result = text
        if heuristic_patterns:
            result = self._decrypt_heuristic_markers(result, heuristic_patterns, tweak)

        # Second pass: decrypt prefix-based tokens
        prefix_patterns = [p for p in patterns if p.kind != "heuristic"]
        if not prefix_patterns:
            return result

        spans = scan(result, prefix_patterns, self._patterns)
        if not spans:
            return result

        parts: list[str] = []
        cursor = 0
        for span in spans:
            parts.append(result[cursor : span.start])
            parts.append(self._transform_span(span, tweak, "decrypt"))
            cursor = span.end
        parts.append(result[cursor:])
        return "".join(parts)

    def _transform_span(
        self, span: TokenSpan, extra_tweak: bytes | None, mode: str
    ) -> str:
        pattern = span.pattern
        body = span.body
        tweak = _make_tweak(pattern.name, extra_tweak)

        if pattern.kind == "heuristic":
            cipher = self._get_cipher(pattern.body_alphabet.radix, len(body))
            result = transform_body(body, pattern.body_alphabet, cipher, mode, tweak)
            if mode == "encrypt":
                return _heuristic_marker(pattern.name) + result
            return result

        if pattern.kind == "simple":
            cipher = self._get_cipher(pattern.body_alphabet.radix, len(body))
            result = transform_body(body, pattern.body_alphabet, cipher, mode, tweak)
            return pattern.prefix + result

        # Structured
        parsed = pattern.parse(body)
        if parsed is None:
            return pattern.prefix + body

        transformed: list[str] = []
        for seg, alphabet in zip(parsed["segments"], parsed["alphabets"]):
            if len(seg) < MIN_SEGMENT_LENGTH:
                transformed.append(seg)
                continue
            cipher = self._get_cipher(alphabet.radix, len(seg))
            transformed.append(transform_body(seg, alphabet, cipher, mode, tweak))

        return pattern.prefix + pattern.format(transformed)

    def _decrypt_heuristic_markers(
        self,
        text: str,
        patterns: list[TokenPattern],
        extra_tweak: bytes | None,
    ) -> str:
        hits: list[dict[str, Any]] = []

        for pattern in patterns:
            if pattern.kind != "heuristic":
                continue
            assert isinstance(pattern, HeuristicTokenPattern)
            marker = _heuristic_marker(pattern.name)

            search_from = 0
            while search_from < len(text):
                idx = text.find(marker, search_from)
                if idx == -1:
                    break

                body_start = idx + len(marker)
                body_end = body_start
                while (
                    body_end < len(text)
                    and body_end - body_start < pattern.max_length
                    and text[body_end] in pattern.body_alphabet.char_to_index
                ):
                    body_end += 1

                body_len = body_end - body_start
                trailing_alpha = (
                    body_end < len(text)
                    and text[body_end] in pattern.body_alphabet.char_to_index
                )
                if (
                    body_len >= pattern.min_length
                    and body_len <= pattern.max_length
                    and not trailing_alpha
                ):
                    hits.append(
                        {
                            "start": idx,
                            "end": body_end,
                            "body": text[body_start:body_end],
                            "pattern_name": pattern.name,
                            "alphabet": pattern.body_alphabet,
                        }
                    )
                    search_from = body_end
                else:
                    search_from = idx + 1

        if not hits:
            return text

        hits.sort(key=lambda h: h["start"])

        parts: list[str] = []
        cursor = 0
        for hit in hits:
            if hit["start"] < cursor:
                continue
            parts.append(text[cursor : hit["start"]])
            tweak = _make_tweak(hit["pattern_name"], extra_tweak)
            cipher = self._get_cipher(hit["alphabet"].radix, len(hit["body"]))
            parts.append(
                transform_body(hit["body"], hit["alphabet"], cipher, "decrypt", tweak)
            )
            cursor = hit["end"]
        parts.append(text[cursor:])
        return "".join(parts)

    def register(self, pattern: TokenPattern) -> None:
        self._assert_alive()
        self._patterns.insert(0, pattern)

    def destroy(self) -> None:
        self._destroyed = True
        for cipher in self._cache.values():
            cipher.destroy()
        self._cache.clear()
        self._key = b"\x00" * len(self._key)


__all__ = [
    "ALPHANUMERIC",
    "ALPHANUMERIC_LOWER",
    "ALPHANUMERIC_UPPER",
    "BASE64",
    "BASE64URL",
    "DIGITS",
    "HEX_LOWER",
    "Alphabet",
    "TokenEncryptor",
    "TokenPattern",
]
