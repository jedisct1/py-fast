from __future__ import annotations

import struct

from fast_cipher.aes import AesEncryptor

AES_BLOCK_SIZE = 16
CMAC_RB = 0x87


def _left_shift_and_xor(data: bytes, xor_byte: int) -> bytes:
    result = bytearray(AES_BLOCK_SIZE)
    carry = 0
    for i in range(AES_BLOCK_SIZE - 1, -1, -1):
        result[i] = ((data[i] << 1) | carry) & 0xFF
        carry = (data[i] >> 7) & 1
    if (data[0] >> 7) & 1:
        result[AES_BLOCK_SIZE - 1] ^= xor_byte
    return bytes(result)


def aes_cmac(key: bytes, message: bytes) -> bytes:
    aes = AesEncryptor(key)

    L = aes.encrypt_block(b"\x00" * AES_BLOCK_SIZE)
    k1 = _left_shift_and_xor(L, CMAC_RB)
    k2 = _left_shift_and_xor(k1, CMAC_RB)

    msg_len = len(message)
    block_count = max(1, (msg_len + AES_BLOCK_SIZE - 1) // AES_BLOCK_SIZE)
    last_block_offset = (block_count - 1) * AES_BLOCK_SIZE
    has_full_last_block = msg_len > 0 and msg_len % AES_BLOCK_SIZE == 0

    last_block = bytearray(AES_BLOCK_SIZE)
    if has_full_last_block:
        for i in range(AES_BLOCK_SIZE):
            last_block[i] = message[last_block_offset + i] ^ k1[i]
    else:
        remaining = msg_len - last_block_offset
        last_block[:remaining] = message[last_block_offset:]
        last_block[remaining] = 0x80
        for i in range(AES_BLOCK_SIZE):
            last_block[i] ^= k2[i]

    state = bytearray(AES_BLOCK_SIZE)
    for block_index in range(block_count - 1):
        offset = block_index * AES_BLOCK_SIZE
        for i in range(AES_BLOCK_SIZE):
            state[i] ^= message[offset + i]
        state[:] = aes.encrypt_block(state)

    for i in range(AES_BLOCK_SIZE):
        state[i] ^= last_block[i]

    return aes.encrypt_block(state)


def derive_key(
    master_key: bytes, input_data: bytes, output_length: int = 32
) -> bytearray:
    if len(master_key) not in (16, 24, 32):
        raise ValueError("Master key must be 16, 24, or 32 bytes")
    if output_length == 0:
        raise ValueError("Output length must be > 0")

    output = bytearray(output_length)
    buffer = bytearray(4 + len(input_data))
    buffer[4:] = input_data

    bytes_generated = 0
    counter = 0
    while bytes_generated < output_length:
        struct.pack_into(">I", buffer, 0, counter)
        cmac_output = aes_cmac(master_key, buffer)
        to_copy = min(output_length - bytes_generated, AES_BLOCK_SIZE)
        output[bytes_generated : bytes_generated + to_copy] = cmac_output[:to_copy]
        bytes_generated += to_copy
        counter += 1

    return output
