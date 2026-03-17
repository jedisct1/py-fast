from __future__ import annotations

from .sbox import SBox
from .types import FastParams


def _mod_add(a: int, b: int, radix: int) -> int:
    if radix == 256:
        return (a + b) & 0xFF
    return (a + b) % radix


def _mod_sub(a: int, b: int, radix: int) -> int:
    if radix == 256:
        return (a - b) & 0xFF
    return (a - b) % radix


def es_layer(params: FastParams, sbox: SBox, data: list[int]) -> None:
    """ES (Expansion-Substitution) forward layer."""
    w = params.branch_dist1
    wp = params.branch_dist2
    ell = params.word_length
    radix = params.radix
    perm = sbox.perm

    s = perm[_mod_add(data[0], data[ell - wp], radix)]
    if w > 0:
        nxt = perm[_mod_sub(s, data[w], radix)]
    else:
        nxt = perm[s]

    # Shift left by 1
    data[:-1] = data[1:]
    data[ell - 1] = nxt


def ds_layer(params: FastParams, sbox: SBox, data: list[int]) -> None:
    """DS (De-Substitution) backward layer."""
    w = params.branch_dist1
    wp = params.branch_dist2
    ell = params.word_length
    radix = params.radix
    inv = sbox.inv

    last = inv[data[ell - 1]]
    if w > 0:
        intermediate = inv[_mod_add(last, data[w - 1], radix)]
    else:
        intermediate = inv[last]
    nxt = _mod_sub(intermediate, data[ell - wp - 1], radix)

    # Shift right by 1
    data[1:] = data[:-1]
    data[0] = nxt
