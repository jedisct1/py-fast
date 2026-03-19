"""Test token encryptor: scanning, encryption, decryption, format preservation."""

import re

import pytest

from fast_cipher.tokens import NO_TWEAK, TokenEncryptor, TokenMapping

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
        encrypted, mappings = self.enc.encrypt(token)
        assert encrypted != token, f"Token was not encrypted: {name}"
        assert len(mappings) >= 1, f"No mappings returned for {name}"
        decrypted = self.enc.decrypt(encrypted)
        assert decrypted == token, f"Roundtrip failed for {name}: got {decrypted}"

    def test_roundtrip_in_context(self):
        text = f"My GitHub token is {SAMPLE_TOKENS['github-pat']} and my AWS key is {SAMPLE_TOKENS['aws-access-key']}."
        encrypted, mappings = self.enc.encrypt(text)
        assert SAMPLE_TOKENS["github-pat"] not in encrypted
        assert SAMPLE_TOKENS["aws-access-key"] not in encrypted
        assert len(mappings) == 2
        decrypted = self.enc.decrypt(encrypted)
        assert decrypted == text

    def test_text_without_tokens_unchanged(self):
        text = "This is a normal sentence with no tokens."
        encrypted, mappings = self.enc.encrypt(text)
        assert encrypted == text
        assert mappings == []

    def test_deterministic(self):
        token = SAMPLE_TOKENS["github-pat"]
        ct1, _ = self.enc.encrypt(token)
        ct2, _ = self.enc.encrypt(token)
        assert ct1 == ct2

    def test_different_keys_different_output(self):
        enc2 = TokenEncryptor(bytes(range(1, 17)))
        token = SAMPLE_TOKENS["github-pat"]
        ct1, _ = self.enc.encrypt(token)
        ct2, _ = enc2.encrypt(token)
        assert ct1 != ct2

    def test_tweak_changes_output(self):
        token = SAMPLE_TOKENS["github-pat"]
        ct1, _ = self.enc.encrypt(token)
        ct2, _ = self.enc.encrypt(token, tweak=b"doc1")
        assert ct1 != ct2

    def test_tweak_roundtrip(self):
        token = SAMPLE_TOKENS["github-pat"]
        tweak = b"my-document-id"
        encrypted, _ = self.enc.encrypt(token, tweak=tweak)
        decrypted = self.enc.decrypt(encrypted, tweak=tweak)
        assert decrypted == token


class TestMappings:
    def setup_method(self):
        self.enc = TokenEncryptor(KEY)

    def test_mapping_fields(self):
        token = SAMPLE_TOKENS["github-pat"]
        encrypted, mappings = self.enc.encrypt(token)
        assert len(mappings) == 1
        m = mappings[0]
        assert isinstance(m, TokenMapping)
        assert m.plaintext == token
        assert m.ciphertext == encrypted
        assert m.pattern_name == "github-pat"

    def test_mapping_dedup_by_ciphertext_and_pattern(self):
        token = SAMPLE_TOKENS["github-pat"]
        text = f"{token} some text {token}"
        _, mappings = self.enc.encrypt(text)
        # Same token twice -> one mapping (deduped)
        assert len(mappings) == 1
        assert mappings[0].plaintext == token

    def test_multiple_different_tokens(self):
        text = f"{SAMPLE_TOKENS['github-pat']} {SAMPLE_TOKENS['aws-access-key']}"
        _, mappings = self.enc.encrypt(text)
        assert len(mappings) == 2
        names = {m.pattern_name for m in mappings}
        assert "github-pat" in names
        assert "aws-access-key" in names

    def test_mapping_enables_provenance_reversal(self):
        """The primary use case: build a registry from mappings, reverse only known tokens."""
        token = SAMPLE_TOKENS["github-pat"]
        text = f"Use this key: {token}"
        encrypted, mappings = self.enc.encrypt(text)

        registry = {m.ciphertext: m.plaintext for m in mappings}

        # Simulate LLM echoing back the ciphertext
        llm_response = f"I found the key: {mappings[0].ciphertext}"
        for ct, pt in registry.items():
            llm_response = llm_response.replace(ct, pt)
        assert token in llm_response


class TestDefaultTweak:
    def test_no_tweak_sentinel_rejected_in_constructor(self):
        with pytest.raises(
            ValueError, match="NO_TWEAK is not valid for the constructor"
        ):
            TokenEncryptor(KEY, tweak=NO_TWEAK)

    def test_constructor_tweak_used_by_default(self):
        tweak = b"session-42"
        enc = TokenEncryptor(KEY, tweak=tweak)
        token = SAMPLE_TOKENS["github-pat"]

        # Should match explicit tweak
        enc_no_default = TokenEncryptor(KEY)
        ct_default, _ = enc.encrypt(token)
        ct_explicit, _ = enc_no_default.encrypt(token, tweak=tweak)
        assert ct_default == ct_explicit

    def test_per_call_tweak_overrides_default(self):
        enc = TokenEncryptor(KEY, tweak=b"default")
        token = SAMPLE_TOKENS["github-pat"]

        ct_default, _ = enc.encrypt(token)
        ct_override, _ = enc.encrypt(token, tweak=b"override")
        assert ct_default != ct_override

    def test_no_tweak_sentinel_ignores_default(self):
        enc = TokenEncryptor(KEY, tweak=b"default")
        enc_bare = TokenEncryptor(KEY)
        token = SAMPLE_TOKENS["github-pat"]

        ct_no_tweak, _ = enc.encrypt(token, tweak=NO_TWEAK)
        ct_bare, _ = enc_bare.encrypt(token)
        assert ct_no_tweak == ct_bare

    def test_no_tweak_decrypt(self):
        enc = TokenEncryptor(KEY, tweak=b"default")
        token = SAMPLE_TOKENS["github-pat"]

        encrypted, _ = enc.encrypt(token, tweak=NO_TWEAK)
        decrypted = enc.decrypt(encrypted, tweak=NO_TWEAK)
        assert decrypted == token

    def test_default_tweak_decrypt_roundtrip(self):
        enc = TokenEncryptor(KEY, tweak=b"session-99")
        token = SAMPLE_TOKENS["github-pat"]

        encrypted, _ = enc.encrypt(token)
        decrypted = enc.decrypt(encrypted)
        assert decrypted == token


class TestFormatPreservation:
    def setup_method(self):
        self.enc = TokenEncryptor(KEY)

    def test_github_format(self):
        token = SAMPLE_TOKENS["github-pat"]
        encrypted, _ = self.enc.encrypt(token)
        assert encrypted.startswith("ghp_")
        assert re.fullmatch(r"ghp_[A-Za-z0-9]{36}", encrypted)

    def test_aws_format(self):
        token = SAMPLE_TOKENS["aws-access-key"]
        encrypted, _ = self.enc.encrypt(token)
        assert encrypted.startswith("AKIA")
        assert re.fullmatch(r"AKIA[A-Z0-9]{16}", encrypted)

    def test_sendgrid_format(self):
        token = SAMPLE_TOKENS["sendgrid"]
        encrypted, _ = self.enc.encrypt(token)
        assert encrypted.startswith("SG.")
        assert re.fullmatch(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", encrypted)

    def test_slack_format(self):
        token = SAMPLE_TOKENS["slack-bot"]
        encrypted, _ = self.enc.encrypt(token)
        assert encrypted.startswith("xoxb-")
        # Structure preserved: prefix-digits-digits-alphanumeric
        parts = encrypted[5:].split("-")
        assert len(parts) >= 3

    def test_length_preserved(self):
        for name, token in SAMPLE_TOKENS.items():
            if name in ("slack-bot", "sendgrid"):
                continue  # structured tokens may vary slightly
            encrypted, _ = self.enc.encrypt(token)
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
        encrypted, mappings = self.enc.encrypt(token)
        assert encrypted.startswith("[ENCRYPTED:fastly]")
        assert len(mappings) == 1
        assert mappings[0].pattern_name == "fastly"
        decrypted = self.enc.decrypt(encrypted)
        assert decrypted == token

    def test_aws_secret_key(self):
        # 40-char base64 with high entropy
        token = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        encrypted, mappings = self.enc.encrypt(token)
        assert encrypted.startswith("[ENCRYPTED:aws-secret-key]")
        assert len(mappings) == 1
        assert mappings[0].pattern_name == "aws-secret-key"
        decrypted = self.enc.decrypt(encrypted)
        assert decrypted == token


class TestTypeFilter:
    def setup_method(self):
        self.enc = TokenEncryptor(KEY)

    def test_filter_by_type(self):
        text = f"{SAMPLE_TOKENS['github-pat']} {SAMPLE_TOKENS['aws-access-key']}"
        encrypted, mappings = self.enc.encrypt(text, types=["github-pat"])
        # GitHub token should be encrypted
        assert SAMPLE_TOKENS["github-pat"] not in encrypted
        # AWS key should NOT be encrypted
        assert SAMPLE_TOKENS["aws-access-key"] in encrypted
        # Only one mapping (github)
        assert len(mappings) == 1
        assert mappings[0].pattern_name == "github-pat"
