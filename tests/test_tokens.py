"""Test token encryptor: scanning, encryption, decryption, format preservation."""

import re

import pytest

from fast_cipher.tokens import TokenEncryptor

KEY = bytes(range(16))

# Sample tokens for each provider
SAMPLE_TOKENS = {
    "github-pat": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
    "anthropic": "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZa",
    "openai": "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGH",
    "aws-access-key": "AKIAIOSFODNN7EXAMPLE",
    "slack-bot": "xoxb-123456789012-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWXab",
    "sendgrid": "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
    "stripe-secret-live": "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXab",
    "gitlab": "glpat-ABCDEFGHIJKLMNOPQRSt",
    "google-api": "AIzaSyCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi",
    "twilio": "SK1234567890abcdef1234567890abcdef",
    "npm": "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
}


class TestTokenEncryptorRoundtrip:
    def setup_method(self):
        self.enc = TokenEncryptor(KEY)

    @pytest.mark.parametrize("name,token", list(SAMPLE_TOKENS.items()))
    def test_roundtrip(self, name, token):
        encrypted = self.enc.encrypt(token)
        assert encrypted != token, f"Token was not encrypted: {name}"
        decrypted = self.enc.decrypt(encrypted)
        assert decrypted == token, f"Roundtrip failed for {name}: got {decrypted}"

    def test_roundtrip_in_context(self):
        text = f"My GitHub token is {SAMPLE_TOKENS['github-pat']} and my AWS key is {SAMPLE_TOKENS['aws-access-key']}."
        encrypted = self.enc.encrypt(text)
        assert SAMPLE_TOKENS["github-pat"] not in encrypted
        assert SAMPLE_TOKENS["aws-access-key"] not in encrypted
        decrypted = self.enc.decrypt(encrypted)
        assert decrypted == text

    def test_text_without_tokens_unchanged(self):
        text = "This is a normal sentence with no tokens."
        assert self.enc.encrypt(text) == text

    def test_deterministic(self):
        token = SAMPLE_TOKENS["github-pat"]
        ct1 = self.enc.encrypt(token)
        ct2 = self.enc.encrypt(token)
        assert ct1 == ct2

    def test_different_keys_different_output(self):
        enc2 = TokenEncryptor(bytes(range(1, 17)))
        token = SAMPLE_TOKENS["github-pat"]
        ct1 = self.enc.encrypt(token)
        ct2 = enc2.encrypt(token)
        assert ct1 != ct2

    def test_tweak_changes_output(self):
        token = SAMPLE_TOKENS["github-pat"]
        ct1 = self.enc.encrypt(token)
        ct2 = self.enc.encrypt(token, tweak=b"doc1")
        assert ct1 != ct2

    def test_tweak_roundtrip(self):
        token = SAMPLE_TOKENS["github-pat"]
        tweak = b"my-document-id"
        encrypted = self.enc.encrypt(token, tweak=tweak)
        decrypted = self.enc.decrypt(encrypted, tweak=tweak)
        assert decrypted == token


class TestFormatPreservation:
    def setup_method(self):
        self.enc = TokenEncryptor(KEY)

    def test_github_format(self):
        token = SAMPLE_TOKENS["github-pat"]
        encrypted = self.enc.encrypt(token)
        assert encrypted.startswith("ghp_")
        assert re.fullmatch(r"ghp_[A-Za-z0-9]{36}", encrypted)

    def test_aws_format(self):
        token = SAMPLE_TOKENS["aws-access-key"]
        encrypted = self.enc.encrypt(token)
        assert encrypted.startswith("AKIA")
        assert re.fullmatch(r"AKIA[A-Z0-9]{16}", encrypted)

    def test_sendgrid_format(self):
        token = SAMPLE_TOKENS["sendgrid"]
        encrypted = self.enc.encrypt(token)
        assert encrypted.startswith("SG.")
        assert re.fullmatch(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", encrypted)

    def test_slack_format(self):
        token = SAMPLE_TOKENS["slack-bot"]
        encrypted = self.enc.encrypt(token)
        assert encrypted.startswith("xoxb-")
        # Structure preserved: prefix-digits-digits-alphanumeric
        parts = encrypted[5:].split("-")
        assert len(parts) >= 3

    def test_length_preserved(self):
        for name, token in SAMPLE_TOKENS.items():
            if name in ("slack-bot", "sendgrid"):
                continue  # structured tokens may vary slightly
            encrypted = self.enc.encrypt(token)
            # For simple tokens, total length should be preserved
            assert len(encrypted) == len(token), (
                f"Length changed for {name}: {len(token)} -> {len(encrypted)}"
            )


class TestHeuristicTokens:
    def setup_method(self):
        self.enc = TokenEncryptor(KEY)

    def test_fastly_token(self):
        # 32-char base64url with high entropy
        token = "5lYCIuNxQuC-WFvIvHNmjO0PvaVqrtos"
        encrypted = self.enc.encrypt(token)
        assert encrypted.startswith("[ENCRYPTED:fastly]")
        decrypted = self.enc.decrypt(encrypted)
        assert decrypted == token

    def test_aws_secret_key(self):
        # 40-char base64 with high entropy
        token = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        encrypted = self.enc.encrypt(token)
        assert encrypted.startswith("[ENCRYPTED:aws-secret-key]")
        decrypted = self.enc.decrypt(encrypted)
        assert decrypted == token


class TestTypeFilter:
    def setup_method(self):
        self.enc = TokenEncryptor(KEY)

    def test_filter_by_type(self):
        text = f"{SAMPLE_TOKENS['github-pat']} {SAMPLE_TOKENS['aws-access-key']}"
        encrypted = self.enc.encrypt(text, types=["github-pat"])
        # GitHub token should be encrypted
        assert SAMPLE_TOKENS["github-pat"] not in encrypted
        # AWS key should NOT be encrypted
        assert SAMPLE_TOKENS["aws-access-key"] in encrypted
