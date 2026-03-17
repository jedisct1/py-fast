from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Alphabet:
    name: str
    chars: str
    radix: int = field(init=False)
    char_to_index: dict[str, int] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if len(self.chars) != len(set(self.chars)):
            raise ValueError(f"Alphabet '{self.name}' contains duplicate characters")
        object.__setattr__(self, "radix", len(self.chars))
        mapping = {ch: i for i, ch in enumerate(self.chars)}
        object.__setattr__(self, "char_to_index", mapping)


DIGITS = Alphabet("digits", "0123456789")
HEX_LOWER = Alphabet("hex-lower", "0123456789abcdef")
ALPHANUMERIC_UPPER = Alphabet(
    "alphanumeric-upper", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
ALPHANUMERIC_LOWER = Alphabet(
    "alphanumeric-lower", "0123456789abcdefghijklmnopqrstuvwxyz"
)
ALPHANUMERIC = Alphabet(
    "alphanumeric", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
BASE64 = Alphabet(
    "base64", "+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
BASE64URL = Alphabet(
    "base64url", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-"
)
