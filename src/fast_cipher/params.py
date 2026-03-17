from __future__ import annotations

import math

from .types import FastParams, InvalidParametersError

SBOX_POOL_SIZE = 256

ROUND_L_VALUES = [2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 16, 32, 50, 64, 100]
ROUND_RADICES = [
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    100,
    128,
    256,
    1000,
    1024,
    10000,
    65536,
]

ROUND_TABLE = [
    [165, 135, 117, 105, 96, 89, 83, 78, 74, 68, 59, 52, 52, 53, 57],
    [131, 107, 93, 83, 76, 70, 66, 62, 59, 54, 48, 46, 47, 48, 53],
    [113, 92, 80, 72, 65, 61, 57, 54, 51, 46, 44, 43, 44, 46, 52],
    [102, 83, 72, 64, 59, 55, 51, 48, 46, 43, 41, 41, 43, 45, 50],
    [94, 76, 66, 59, 54, 50, 47, 44, 42, 41, 39, 39, 42, 44, 50],
    [88, 72, 62, 56, 51, 47, 44, 42, 40, 39, 38, 38, 41, 43, 49],
    [83, 68, 59, 53, 48, 45, 42, 39, 39, 38, 37, 37, 40, 43, 49],
    [79, 65, 56, 50, 46, 43, 40, 38, 38, 37, 36, 37, 40, 42, 48],
    [76, 62, 54, 48, 44, 41, 38, 37, 37, 36, 35, 36, 39, 42, 48],
    [73, 60, 52, 47, 43, 39, 37, 36, 36, 35, 34, 36, 39, 41, 48],
    [71, 58, 50, 45, 41, 38, 36, 36, 35, 34, 34, 35, 39, 41, 47],
    [69, 57, 49, 44, 40, 37, 36, 35, 34, 34, 33, 35, 38, 41, 47],
    [67, 55, 48, 43, 39, 36, 35, 34, 34, 33, 33, 35, 38, 41, 47],
    [40, 33, 28, 27, 26, 26, 25, 25, 25, 26, 26, 30, 34, 37, 44],
    [38, 31, 27, 26, 25, 25, 25, 25, 25, 25, 26, 30, 34, 37, 44],
    [33, 27, 25, 24, 23, 23, 23, 23, 23, 24, 25, 29, 33, 37, 44],
    [32, 22, 21, 21, 21, 21, 21, 21, 21, 22, 23, 28, 32, 36, 43],
    [32, 22, 21, 21, 21, 21, 21, 21, 21, 22, 23, 28, 32, 36, 43],
    [32, 22, 18, 18, 18, 18, 19, 19, 19, 20, 21, 27, 32, 35, 42],
    [32, 22, 17, 17, 17, 17, 17, 18, 18, 19, 21, 26, 31, 35, 42],
]


def _interpolate(x: float, x0: float, x1: float, y0: float, y1: float) -> float:
    if x1 == x0:
        return y0
    ratio = (x - x0) / (x1 - x0)
    if ratio <= 0:
        return y0
    if ratio >= 1:
        return y1
    return y0 + ratio * (y1 - y0)


def _rounds_for_row(row_index: int, ell: int) -> float:
    row = ROUND_TABLE[row_index]
    last_index = len(ROUND_L_VALUES) - 1
    max_word_length = ROUND_L_VALUES[last_index]

    if ell <= ROUND_L_VALUES[0]:
        return row[0]

    if ell >= max_word_length:
        base_rounds = row[last_index]
        return max(base_rounds, base_rounds * math.sqrt(ell / max_word_length))

    for i in range(1, last_index + 1):
        if ell <= ROUND_L_VALUES[i]:
            return _interpolate(
                ell,
                ROUND_L_VALUES[i - 1],
                ROUND_L_VALUES[i],
                row[i - 1],
                row[i],
            )

    return row[last_index]


def _lookup_recommended_rounds(radix: int, ell: int) -> float:
    last_index = len(ROUND_RADICES) - 1

    if radix <= ROUND_RADICES[0]:
        return _rounds_for_row(0, ell)

    if radix >= ROUND_RADICES[last_index]:
        return _rounds_for_row(last_index, ell)

    log_radix = math.log(radix)
    for i in range(1, last_index + 1):
        if radix <= ROUND_RADICES[i]:
            return _interpolate(
                log_radix,
                math.log(ROUND_RADICES[i - 1]),
                math.log(ROUND_RADICES[i]),
                _rounds_for_row(i - 1, ell),
                _rounds_for_row(i, ell),
            )

    return _rounds_for_row(last_index, ell)


def calculate_recommended_params(
    radix: int,
    word_length: int,
    security_level: int = 128,
) -> FastParams:
    if radix < 4 or radix > 256:
        raise InvalidParametersError("radix must be between 4 and 256")
    if word_length < 1:
        raise InvalidParametersError("word_length must be >= 1")

    sec_level = security_level if security_level != 0 else 128

    w_candidate = math.ceil(math.sqrt(word_length))
    branch_dist1 = max(min(w_candidate, word_length - 2), 0)
    branch_dist2 = max(branch_dist1 - 1, 1)

    rounds = _lookup_recommended_rounds(radix, word_length)
    if rounds < 1.0:
        rounds = 1.0
    rounds_u = math.ceil(rounds)
    num_layers = rounds_u * word_length

    return FastParams(
        radix=radix,
        word_length=word_length,
        sbox_count=SBOX_POOL_SIZE,
        num_layers=num_layers,
        branch_dist1=branch_dist1,
        branch_dist2=branch_dist2,
        security_level=sec_level,
    )
