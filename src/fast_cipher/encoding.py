from __future__ import annotations

import struct

from .types import FastParams

_LABEL_INSTANCE1 = b"instance1"
_LABEL_INSTANCE2 = b"instance2"
_LABEL_FPE_POOL = b"FPE Pool"
_LABEL_FPE_SEQ = b"FPE SEQ"
_LABEL_TWEAK = b"tweak"


def _u32be(value: int) -> bytes:
    return struct.pack(">I", value)


def encode_parts(parts: list[bytes]) -> bytes:
    buf = bytearray(_u32be(len(parts)))
    for part in parts:
        buf.extend(_u32be(len(part)))
        buf.extend(part)
    return bytes(buf)


def build_setup1_input(params: FastParams) -> bytes:
    return encode_parts(
        [
            _LABEL_INSTANCE1,
            _u32be(params.radix),
            _u32be(params.sbox_count),
            _LABEL_FPE_POOL,
        ]
    )


def build_setup2_input(params: FastParams, tweak: bytes) -> bytes:
    return encode_parts(
        [
            _LABEL_INSTANCE1,
            _u32be(params.radix),
            _u32be(params.sbox_count),
            _LABEL_INSTANCE2,
            _u32be(params.word_length),
            _u32be(params.num_layers),
            _u32be(params.branch_dist1),
            _u32be(params.branch_dist2),
            _LABEL_FPE_SEQ,
            _LABEL_TWEAK,
            tweak,
        ]
    )
