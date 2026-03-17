from dataclasses import dataclass


@dataclass(frozen=True)
class FastParams:
    radix: int
    word_length: int
    sbox_count: int
    num_layers: int
    branch_dist1: int
    branch_dist2: int
    security_level: int = 128


class FastError(Exception):
    pass


class InvalidRadixError(FastError):
    pass


class InvalidWordLengthError(FastError):
    pass


class InvalidSBoxCountError(FastError):
    pass


class InvalidBranchDistError(FastError):
    pass


class InvalidLengthError(FastError):
    pass


class InvalidValueError(FastError):
    pass


class InvalidParametersError(FastError):
    pass


class InvalidKeyError(FastError):
    pass
