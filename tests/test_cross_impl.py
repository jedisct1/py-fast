"""Cross-implementation tests: verify Python token encryptor produces
output that can be decrypted by the JS implementation and vice versa.

We generate test vectors by running the JS implementation via Node.js,
then verify Python can decrypt them (and vice versa).
"""

import json
import subprocess

import pytest

from fast_cipher.tokens import TokenEncryptor

KEY_HEX = "000102030405060708090a0b0c0d0e0f"
KEY = bytes.fromhex(KEY_HEX)

CROSS_IMPL_TOKENS = [
    ("github-pat", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"),
    ("aws-access-key", "AKIAIOSFODNN7EXAMPLE"),
    (
        "openai",
        "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGH",
    ),
    ("stripe-secret-live", "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXab"),
]

JS_SCRIPT = """
const { TokenEncryptor } = require('./dist/tokens/index.js');
const key = Buffer.from(process.argv[1], 'hex');
const enc = new TokenEncryptor(key);
const tokens = JSON.parse(process.argv[2]);
const results = {};
for (const [name, token] of tokens) {
    results[name] = {
        encrypted: enc.encrypt(token),
        token: token,
    };
}
console.log(JSON.stringify(results));
enc.destroy();
"""


def _run_js_encrypt():
    """Run JS token encryptor and return encrypted tokens."""
    try:
        result = subprocess.run(
            ["node", "-e", JS_SCRIPT, KEY_HEX, json.dumps(CROSS_IMPL_TOKENS)],
            capture_output=True,
            text=True,
            cwd="/Users/j/src/js-fast",
            timeout=30,
        )
        if result.returncode != 0:
            pytest.skip(f"JS implementation not available: {result.stderr}")
        return json.loads(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip("Node.js not available")


@pytest.mark.skipif(
    not subprocess.run(["which", "node"], capture_output=True).returncode == 0,
    reason="Node.js not installed",
)
class TestCrossImplementation:
    def test_python_decrypts_js_output(self):
        """Verify Python can decrypt what JS encrypted."""
        js_results = _run_js_encrypt()
        enc = TokenEncryptor(KEY)

        for name, token in CROSS_IMPL_TOKENS:
            js_encrypted = js_results[name]["encrypted"]
            py_decrypted = enc.decrypt(js_encrypted)
            assert py_decrypted == token, (
                f"Python failed to decrypt JS output for {name}: "
                f"JS encrypted={js_encrypted!r}, Python decrypted={py_decrypted!r}"
            )

    def test_js_and_python_produce_same_ciphertext(self):
        """Verify Python and JS produce identical ciphertext (deterministic)."""
        js_results = _run_js_encrypt()
        enc = TokenEncryptor(KEY)

        for name, token in CROSS_IMPL_TOKENS:
            py_encrypted, _ = enc.encrypt(token)
            js_encrypted = js_results[name]["encrypted"]
            assert py_encrypted == js_encrypted, (
                f"Ciphertext mismatch for {name}: "
                f"Python={py_encrypted!r}, JS={js_encrypted!r}"
            )
