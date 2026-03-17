"""Test FAST cipher against known test vectors from the Go implementation."""

import pytest

from fast_cipher import FastCipher, calculate_recommended_params


# Test vectors freshly generated from go-fast (2026-03-17)
# All use radix=256 (byte-level FPE)
GO_TEST_VECTORS = [
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "00",
        "expected": "e1",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "0025",
        "expected": "0aa6",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "00254a",
        "expected": "dc1e42",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "00254a6f94",
        "expected": "92e633f19b",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "00254a6f94b9de03",
        "expected": "54149f51b25fccdd",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "00254a6f94b9de03284d7297bce1062b",
        "expected": "5dc4d5bbd00026b67ab3fa15f37a9e31",
    },
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "00254a6f94b9de03284d7297bce1062b50759abfe4092e53789dc2e70c31567b",
        "expected": "610933225fbfa5edf41e786213d5cf51a3687649a65dba7cfc60dbac013eb17f",
    },
    # AES-192 key
    {
        "key": "000102030405060708090a0b0c0d0e0f1011121314151617",
        "plaintext": "00254a6f94b9de03284d7297bce1062b",
        "expected": "69f3c63f2244117f15452aa24cf06e6a",
    },
    # AES-256 key
    {
        "key": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "plaintext": "00254a6f94b9de03284d7297bce1062b",
        "expected": "2a5ac4d4d53f13d84c33e0c5a9731f02",
    },
    # With tweak
    {
        "key": "000102030405060708090a0b0c0d0e0f",
        "plaintext": "00254a6f94b9de03284d7297bce1062b",
        "tweak": "746573742d747765616b",
        "expected": "ab2350b978be45a2bfcec6481508b15c",
    },
]

# Cross-implementation vector from Zig (radix 10, word length 16)
ZIG_TEST_VECTOR = {
    "key": bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C"),
    "tweak": bytes.fromhex("0011223344556677"),
    "plaintext": [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6],
    "expected": [4, 6, 7, 8, 2, 9, 3, 2, 5, 1, 2, 5, 6, 9, 8, 2],
}


@pytest.mark.parametrize(
    "vector",
    GO_TEST_VECTORS,
    ids=[
        f"radix256-len{len(v['plaintext']) // 2}-{'tweak' if 'tweak' in v else 'no_tweak'}-key{len(v['key']) // 2}"
        for v in GO_TEST_VECTORS
    ],
)
def test_go_vectors(vector):
    key = bytes.fromhex(vector["key"])
    plaintext = bytes.fromhex(vector["plaintext"])
    expected = bytes.fromhex(vector["expected"])
    tweak = bytes.fromhex(vector.get("tweak", ""))

    word_length = len(plaintext)
    params = calculate_recommended_params(256, word_length)
    cipher = FastCipher(params, key)

    ciphertext = cipher.encrypt_bytes(plaintext, tweak)
    assert ciphertext == expected, (
        f"Encryption mismatch: got {ciphertext.hex()}, expected {expected.hex()}"
    )

    decrypted = cipher.decrypt_bytes(ciphertext, tweak)
    assert decrypted == plaintext, (
        f"Decryption mismatch: got {decrypted.hex()}, expected {plaintext.hex()}"
    )


def test_zig_radix10_vector():
    v = ZIG_TEST_VECTOR
    params = calculate_recommended_params(10, 16)
    cipher = FastCipher(params, v["key"])

    ciphertext = cipher.encrypt(v["plaintext"], v["tweak"])
    assert ciphertext == v["expected"], (
        f"Encryption mismatch: got {ciphertext}, expected {v['expected']}"
    )

    decrypted = cipher.decrypt(ciphertext, v["tweak"])
    assert decrypted == v["plaintext"]


def test_roundtrip_various_radixes():
    key = bytes(range(16))
    for radix in [4, 10, 16, 36, 62, 100, 128, 256]:
        for word_length in [2, 4, 8, 16]:
            params = calculate_recommended_params(radix, word_length)
            cipher = FastCipher(params, key)
            plaintext = [i % radix for i in range(word_length)]
            ciphertext = cipher.encrypt(plaintext)
            decrypted = cipher.decrypt(ciphertext)
            assert decrypted == plaintext, (
                f"Roundtrip failed for radix={radix}, word_length={word_length}"
            )


def test_different_keys_different_output():
    params = calculate_recommended_params(256, 16)
    key1 = bytes(range(16))
    key2 = bytes(range(1, 17))
    cipher1 = FastCipher(params, key1)
    cipher2 = FastCipher(params, key2)
    plaintext = bytes(range(16))
    ct1 = cipher1.encrypt_bytes(plaintext)
    ct2 = cipher2.encrypt_bytes(plaintext)
    assert ct1 != ct2


def test_different_tweaks_different_output():
    params = calculate_recommended_params(256, 16)
    key = bytes(range(16))
    cipher = FastCipher(params, key)
    plaintext = bytes(range(16))
    ct1 = cipher.encrypt_bytes(plaintext, b"tweak1")
    ct2 = cipher.encrypt_bytes(plaintext, b"tweak2")
    assert ct1 != ct2


def test_deterministic():
    params = calculate_recommended_params(256, 16)
    key = bytes(range(16))
    cipher = FastCipher(params, key)
    plaintext = bytes(range(16))
    ct1 = cipher.encrypt_bytes(plaintext)
    ct2 = cipher.encrypt_bytes(plaintext)
    assert ct1 == ct2
