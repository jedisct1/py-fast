from __future__ import annotations

from typing import Literal

from ..cipher import FastCipher
from .alphabets import Alphabet


def chars_to_indices(body: str, alphabet: Alphabet) -> list[int]:
    return [alphabet.char_to_index[ch] for ch in body]


def indices_to_chars(indices: list[int], alphabet: Alphabet) -> str:
    return "".join(alphabet.chars[i] for i in indices)


def transform_body(
    body: str,
    alphabet: Alphabet,
    cipher: FastCipher,
    mode: Literal["encrypt", "decrypt"],
    tweak: bytes,
) -> str:
    indices = chars_to_indices(body, alphabet)
    if mode == "encrypt":
        result = cipher.encrypt(indices, tweak)
    else:
        result = cipher.decrypt(indices, tweak)
    return indices_to_chars(result, alphabet)
