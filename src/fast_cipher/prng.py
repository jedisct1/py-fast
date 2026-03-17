from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB

AES_BLOCK_SIZE = 16


class PrngState:
    """AES-128 ECB counter-mode PRNG matching C/Zig/JS reference implementations."""

    def __init__(self, key: bytes, nonce: bytes) -> None:
        self._encryptor = Cipher(AES(key), ECB()).encryptor()
        self._counter = bytearray(nonce)
        self._buffer = bytearray(AES_BLOCK_SIZE)
        self._buffer_pos = AES_BLOCK_SIZE  # force refill on first use

    def _increment_counter(self) -> None:
        for i in range(AES_BLOCK_SIZE - 1, -1, -1):
            self._counter[i] = (self._counter[i] + 1) & 0xFF
            if self._counter[i] != 0:
                break

    def _encrypt_block(self) -> None:
        self._buffer[:] = self._encryptor.update(self._counter)

    def get_bytes(self, n: int) -> bytes:
        output = bytearray(n)
        offset = 0
        while offset < n:
            if self._buffer_pos == AES_BLOCK_SIZE:
                self._increment_counter()
                self._encrypt_block()
                self._buffer_pos = 0
            chunk = min(n - offset, AES_BLOCK_SIZE - self._buffer_pos)
            output[offset : offset + chunk] = self._buffer[
                self._buffer_pos : self._buffer_pos + chunk
            ]
            self._buffer_pos += chunk
            offset += chunk
        return bytes(output)

    def next_u32(self) -> int:
        data = self.get_bytes(4)
        return struct.unpack(">I", data)[0]

    def uniform(self, bound: int) -> int:
        """Unbiased uniform random in [0, bound) using Lemire's method."""
        if bound <= 1:
            return 0
        threshold = (0x100000000 - bound) % bound
        while True:
            r = self.next_u32()
            product = r * bound
            low = product & 0xFFFFFFFF
            if low >= threshold:
                return product >> 32


def split_key_material(
    key_material: bytes, zeroize_iv_suffix: bool
) -> tuple[bytes, bytes]:
    key = key_material[:16]
    iv = bytearray(key_material[16:32])
    if zeroize_iv_suffix:
        iv[AES_BLOCK_SIZE - 1] = 0
        iv[AES_BLOCK_SIZE - 2] = 0
    return key, bytes(iv)


def generate_sequence(
    num_layers: int, pool_size: int, key_material: bytes
) -> list[int]:
    key, iv = split_key_material(key_material, zeroize_iv_suffix=True)
    prng = PrngState(key, iv)
    return [prng.uniform(pool_size) for _ in range(num_layers)]
