from __future__ import annotations

from .core import cdec, cenc
from .encoding import build_setup1_input, build_setup2_input
from .prf import derive_key
from .prng import generate_sequence
from .sbox import generate_sbox_pool
from .types import (
    FastParams,
    InvalidBranchDistError,
    InvalidKeyError,
    InvalidLengthError,
    InvalidRadixError,
    InvalidSBoxCountError,
    InvalidValueError,
    InvalidWordLengthError,
)

DERIVED_KEY_SIZE = 32


class FastCipher:
    """FAST format-preserving encryption cipher."""

    def __init__(self, params: FastParams, key: bytes) -> None:
        _validate_params(params, key)
        self.params = params
        self._master_key = bytes(key)

        pool_key_material = derive_key(
            key, build_setup1_input(params), DERIVED_KEY_SIZE
        )
        self._sboxes = generate_sbox_pool(
            params.radix, params.sbox_count, bytes(pool_key_material)
        )

        self._cached_tweak: bytes | None = None
        self._cached_seq: list[int] | None = None
        self._destroyed = False

    def _ensure_sequence(self, tweak: bytes) -> list[int]:
        if self._cached_seq is not None and self._cached_tweak == tweak:
            return self._cached_seq

        seq_key_material = derive_key(
            self._master_key,
            build_setup2_input(self.params, tweak),
            DERIVED_KEY_SIZE,
        )
        seq = generate_sequence(
            self.params.num_layers,
            self.params.sbox_count,
            bytes(seq_key_material),
        )
        self._cached_tweak = tweak
        self._cached_seq = seq
        return seq

    def _assert_alive(self) -> None:
        if self._destroyed:
            raise RuntimeError("FastCipher has been destroyed")

    def _validate_input(self, data: bytes | list[int]) -> list[int]:
        values = list(data)
        if len(values) != self.params.word_length:
            raise InvalidLengthError(
                f"Expected {self.params.word_length} elements, got {len(values)}"
            )
        for v in values:
            if not (0 <= v < self.params.radix):
                raise InvalidValueError(
                    f"Value {v} out of range [0, {self.params.radix})"
                )
        return values

    def encrypt(self, plaintext: bytes | list[int], tweak: bytes = b"") -> list[int]:
        self._assert_alive()
        values = self._validate_input(plaintext)
        seq = self._ensure_sequence(tweak)
        return cenc(self.params, self._sboxes, seq, values)

    def decrypt(self, ciphertext: bytes | list[int], tweak: bytes = b"") -> list[int]:
        self._assert_alive()
        values = self._validate_input(ciphertext)
        seq = self._ensure_sequence(tweak)
        return cdec(self.params, self._sboxes, seq, values)

    def encrypt_bytes(self, plaintext: bytes, tweak: bytes = b"") -> bytes:
        return bytes(self.encrypt(plaintext, tweak))

    def decrypt_bytes(self, ciphertext: bytes, tweak: bytes = b"") -> bytes:
        return bytes(self.decrypt(ciphertext, tweak))

    def destroy(self) -> None:
        self._destroyed = True
        self._master_key = b"\x00" * len(self._master_key)
        self._sboxes = []
        self._cached_seq = None
        self._cached_tweak = None


def _validate_params(params: FastParams, key: bytes) -> None:
    if params.radix < 4 or params.radix > 256:
        raise InvalidRadixError("Radix must be between 4 and 256")

    if params.word_length < 1:
        raise InvalidWordLengthError("Word length must be >= 1")

    if params.num_layers < 1:
        raise InvalidWordLengthError("num_layers must be >= 1")

    if params.word_length > 1 and params.num_layers % params.word_length != 0:
        raise InvalidWordLengthError("num_layers must be a multiple of word_length")

    if params.sbox_count < 1:
        raise InvalidSBoxCountError("S-box count must be >= 1")

    if params.branch_dist1 < 0:
        raise InvalidBranchDistError("branch_dist1 must be >= 0")

    if params.branch_dist2 < 0:
        raise InvalidBranchDistError("branch_dist2 must be >= 0")

    if params.word_length > 1:
        if params.branch_dist1 > params.word_length - 2:
            raise InvalidBranchDistError("branch_dist1 must be <= word_length - 2")
        if params.branch_dist2 == 0 or params.branch_dist2 > params.word_length - 1:
            raise InvalidBranchDistError("branch_dist2 is out of valid range")

    if len(key) not in (16, 24, 32):
        raise InvalidKeyError("Key must be 16, 24, or 32 bytes")
