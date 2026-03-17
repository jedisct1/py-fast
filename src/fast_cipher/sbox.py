from __future__ import annotations

from dataclasses import dataclass

from .prng import PrngState, split_key_material


@dataclass
class SBox:
    perm: list[int]
    inv: list[int]


def generate_sbox(radix: int, prng: PrngState) -> SBox:
    perm = list(range(radix))
    for i in range(radix - 1, 0, -1):
        j = prng.uniform(i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    inv = [0] * radix
    for i in range(radix):
        inv[perm[i]] = i
    return SBox(perm=perm, inv=inv)


def generate_sbox_pool(radix: int, count: int, key_material: bytes) -> list[SBox]:
    key, iv = split_key_material(key_material, zeroize_iv_suffix=False)
    prng = PrngState(key, iv)
    return [generate_sbox(radix, prng) for _ in range(count)]
