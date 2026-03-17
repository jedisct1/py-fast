# FAST format-preserving cipher for Python

A pure Python implementation of the [FAST cipher](https://github.com/jedisct1/fast),
a format-preserving encryption (FPE) scheme designed for tokenizing API keys, credentials, and other structured secrets.

For prefix-based tokens (GitHub, AWS, Stripe, etc.), encrypted output keeps the exact same format
(length, prefix, character set) as the originals, so they pass through systems that validate token formats.
Heuristic tokens (Fastly, AWS secret keys) are wrapped in a tagged marker since they have no distinguishing prefix.

Fully interoperable with the [C](https://github.com/jedisct1/c-fast),
[Zig](https://github.com/jedisct1/zig-fast),
[Go](https://github.com/jedisct1/go-fast), and
[JavaScript](https://github.com/nickvdyck/js-fast) implementations.

## Installation

```bash
pip install fast-cipher
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv add fast-cipher
```

## Quick start

The most common use case is encrypting tokens and API keys found inside a block of text.
`TokenEncryptor` handles scanning, encrypting, and decrypting automatically:

```python
import os
from fast_cipher.tokens import TokenEncryptor

key = os.urandom(32)  # AES-128, AES-192, or AES-256
encryptor = TokenEncryptor(key)

text = """
Here are the credentials for the staging environment:
GitHub token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
AWS access key: AKIAIOSFODNN7EXAMPLE
Stripe key: sk_live_ABCDEFGHIJKLMNOPQRSTUVWXab
"""

encrypted = encryptor.encrypt(text)
```

For prefix-based tokens the result still looks like valid tokens: same prefixes, same lengths, same
character sets, but the secret parts have been replaced with ciphertext. Decryption restores the original
text exactly:

```python
decrypted = encryptor.decrypt(encrypted)
assert decrypted == text
```

## Tweaks

A tweak is optional context data that gets mixed into the encryption.
The same plaintext encrypted with different tweaks produces different ciphertext,
which is useful for binding tokens to a specific user, session, or tenant:

```python
enc_alice = encryptor.encrypt(text, tweak=b"user-alice")
enc_bob = encryptor.encrypt(text, tweak=b"user-bob")

assert enc_alice != enc_bob

# Each can only be decrypted with the matching tweak
assert encryptor.decrypt(enc_alice, tweak=b"user-alice") == text
assert encryptor.decrypt(enc_bob, tweak=b"user-bob") == text
```

## Filtering by token type

If you only want to encrypt certain kinds of tokens and leave the rest as-is,
pass a `types` list with the pattern names you care about:

```python
text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij and AKIAIOSFODNN7EXAMPLE"

encrypted = encryptor.encrypt(text, types=["github-pat"])
# The GitHub token is encrypted, but the AWS key is untouched
```

## Supported token types

The following patterns are detected and encrypted out of the box:

| Provider       | Pattern name(s)                                                                          | Prefix                                         |
| -------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------- |
| Anthropic      | `anthropic`                                                                              | `sk-ant-api03-`                                |
| AWS            | `aws-access-key`                                                                         | `AKIA`                                         |
| Datadog        | `datadog`                                                                                | `ddapi_`                                       |
| GitHub         | `github-pat`, `github-oauth`, `github-user`, `github-server`, `github-refresh`           | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`         |
| GitLab         | `gitlab`                                                                                 | `glpat-`                                       |
| Google         | `google-api`                                                                             | `AIza`                                         |
| Grafana        | `grafana`                                                                                | `glc_`                                         |
| HuggingFace    | `huggingface`                                                                            | `hf_`                                          |
| npm            | `npm`                                                                                    | `npm_`                                         |
| OpenAI         | `openai`, `openai-legacy`                                                                | `sk-proj-`, `sk-`                              |
| PyPI           | `pypi`                                                                                   | `pypi-`                                        |
| SendGrid       | `sendgrid`                                                                               | `SG.`                                          |
| Slack          | `slack-bot`, `slack-user`                                                                | `xoxb-`, `xoxp-`                               |
| Stripe         | `stripe-secret-live`, `stripe-publish-live`, `stripe-secret-test`, `stripe-publish-test` | `sk_live_`, `pk_live_`, `sk_test_`, `pk_test_` |
| Supabase       | `supabase`                                                                               | `sbp_`                                         |
| Twilio         | `twilio`                                                                                 | `SK`                                           |
| Vercel         | `vercel`                                                                                 | `vercel_`                                      |
| Fastly         | `fastly`                                                                                 | *(heuristic, no prefix)*                       |
| AWS Secret Key | `aws-secret-key`                                                                         | *(heuristic, no prefix)*                       |

Heuristic patterns don't rely on a prefix. They look for strings with high entropy and mixed character classes, which is how secrets like Fastly tokens and AWS secret keys are typically formatted. Because there is no distinguishing prefix, encrypted output is wrapped in an `[ENCRYPTED:<name>]` marker. `decrypt()` will attempt to unwrap anything matching that marker pattern, so avoid feeding text containing literal `[ENCRYPTED:...]` strings that were not produced by `encrypt()`.

## Custom token patterns

You can register your own patterns for tokens that aren't covered by the built-in set.
A `SimpleTokenPattern` works for anything that has a fixed prefix followed by a body with a known alphabet:

```python
from fast_cipher.tokens import ALPHANUMERIC, TokenEncryptor
from fast_cipher.tokens.types import SimpleTokenPattern

my_pattern = SimpleTokenPattern(
    name="myapp-api-key",
    prefix="myapp_",
    body_regex="[A-Za-z0-9]{32}",
    body_alphabet=ALPHANUMERIC,
    min_body_length=32,
)

key = os.urandom(32)
encryptor = TokenEncryptor(key)
encryptor.register(my_pattern)

text = "key: myapp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
encrypted = encryptor.encrypt(text)
decrypted = encryptor.decrypt(encrypted)
assert decrypted == text
```

Registered patterns take priority over built-in ones.

The available alphabets are `DIGITS`, `HEX_LOWER`, `ALPHANUMERIC_UPPER`, `ALPHANUMERIC_LOWER`, `ALPHANUMERIC`, `BASE64`, and `BASE64URL`.
You can also create your own with `Alphabet(name="my-abc", chars="abc...")`.

## Low-level cipher

`TokenEncryptor` is built on top of `FastCipher`, which you can use directly when you need format-preserving encryption for arbitrary data. It works on sequences of integers in a given radix (base).

For example, to encrypt an 8-digit decimal number:

```python
from fast_cipher import FastCipher, calculate_recommended_params

params = calculate_recommended_params(radix=10, word_length=8)
key = os.urandom(32)
cipher = FastCipher(params, key)

plaintext = [1, 2, 3, 4, 5, 6, 7, 8]
ciphertext = cipher.encrypt(plaintext)

# Result is still 8 digits, each between 0 and 9
assert len(ciphertext) == 8
assert all(0 <= d < 10 for d in ciphertext)

decrypted = cipher.decrypt(ciphertext)
assert decrypted == plaintext
```

For raw bytes, use radix 256 with the `encrypt_bytes`/`decrypt_bytes` convenience methods:

```python
params = calculate_recommended_params(radix=256, word_length=16)
cipher = FastCipher(params, key)

ciphertext = cipher.encrypt_bytes(b"sensitive data!!")
plaintext = cipher.decrypt_bytes(ciphertext)
assert plaintext == b"sensitive data!!"
```

## Cleanup

When you're done with an encryptor or cipher, call `destroy()` to invalidate the instance:

```python
encryptor.destroy()
```

After `destroy()`, any further calls to `encrypt()` or `decrypt()` will raise a `RuntimeError`.
The method overwrites key references with zero-filled placeholders and clears internal state,
but Python's garbage collector may retain copies of the original key bytes in memory.
For applications that require guaranteed memory scrubbing, use a C-level implementation instead.

## Cross-implementation compatibility

Ciphertext produced by any FAST implementation (C, Zig, Go, JavaScript, Python) can be decrypted by any other, as long as the key, radix, word length, and tweak match. This library is tested against the Go test vectors and cross-validated against the JavaScript implementation.
