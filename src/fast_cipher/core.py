from __future__ import annotations

from .layers import ds_layer, es_layer
from .sbox import SBox
from .types import FastParams


def cenc(
    params: FastParams,
    sboxes: list[SBox],
    seq: list[int],
    plaintext: list[int],
) -> list[int]:
    """Component encryption: apply all ES layers in forward order."""
    data = list(plaintext)
    if params.word_length == 1:
        for layer in range(params.num_layers):
            data[0] = sboxes[seq[layer]].perm[data[0]]
        return data
    for layer in range(params.num_layers):
        es_layer(params, sboxes[seq[layer]], data)
    return data


def cdec(
    params: FastParams,
    sboxes: list[SBox],
    seq: list[int],
    ciphertext: list[int],
) -> list[int]:
    """Component decryption: apply all DS layers in reverse order."""
    data = list(ciphertext)
    if params.word_length == 1:
        for layer in range(params.num_layers - 1, -1, -1):
            data[0] = sboxes[seq[layer]].inv[data[0]]
        return data
    for layer in range(params.num_layers - 1, -1, -1):
        ds_layer(params, sboxes[seq[layer]], data)
    return data
