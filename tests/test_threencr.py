"""Tests for the Python implementation of 3ncr.org v1."""

from __future__ import annotations

import os

import pytest

from threencr import HEADER_V1, TokenCrypt, TokenCryptError

# Canonical v1 envelope test vectors — shared with Go, Node, PHP, and other
# implementations. The 32-byte AES key was originally derived via the legacy
# PBKDF2-SHA3-256 KDF with secret="a", salt="b", iterations=1000; this Python
# library only supports the modern KDFs, so the derived key is hardcoded here
# so we can still verify envelope-level interop.
CANONICAL_KEY = bytes.fromhex(
    "2f84151869d7d2255d62b3320e97429bde5aac04a0573b2468529a7417515f87"
)
CANONICAL_VECTORS = [
    ("a", "3ncr.org/1#I09Dwt6q05ZrH8GQ0cp+g9Jm0hD0BmCwEdylCh8"),
    ("test", "3ncr.org/1#Y3/v2PY7kYQgveAn4AJ8zP+oOuysbs5btYLZ9vl8DLc"),
    (
        "08019215-B205-4416-B2FB-132962F9952F",
        "3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ",
    ),
    (
        "перевірка",
        "3ncr.org/1#EPw7S5+BG6hn/9Sjf6zoYUCdwlzweeB+ahBIabUD6NogAcevXszOGHz9Jzv4vQ",
    ),
]


class TestCanonicalVectors:
    @pytest.mark.parametrize("plaintext,encrypted", CANONICAL_VECTORS)
    def test_decrypts_canonical_vector(self, plaintext: str, encrypted: str) -> None:
        tc = TokenCrypt.from_raw_key(CANONICAL_KEY)
        assert tc.decrypt_if_3ncr(encrypted) == plaintext

    @pytest.mark.parametrize("plaintext,encrypted", CANONICAL_VECTORS)
    def test_round_trip(self, plaintext: str, encrypted: str) -> None:
        tc = TokenCrypt.from_raw_key(CANONICAL_KEY)
        enc = tc.encrypt_3ncr(plaintext)
        assert enc.startswith(HEADER_V1)
        assert tc.decrypt_if_3ncr(enc) == plaintext


class TestRoundTripEdgeCases:
    """Round-trip axes recommended by the 3ncr.org spec."""

    @pytest.mark.parametrize(
        "plaintext",
        [
            "",  # empty string
            "x",  # single ASCII character
            "hello, world",  # short ASCII
            "08019215-B205-4416-B2FB-132962F9952F",  # UUID-shaped
            "перевірка 🌍 中文 ✓",  # multibyte UTF-8 (Cyrillic, emoji, CJK)
            "a" * 4096,  # long string crossing multiple AES blocks
        ],
    )
    def test_round_trip(self, plaintext: str) -> None:
        tc = TokenCrypt.from_raw_key(os.urandom(32))
        assert tc.decrypt_if_3ncr(tc.encrypt_3ncr(plaintext)) == plaintext


class TestEnvelopePassthrough:
    def test_non_3ncr_returned_unchanged(self) -> None:
        tc = TokenCrypt.from_raw_key(os.urandom(32))
        assert tc.decrypt_if_3ncr("plain config value") == "plain config value"

    def test_empty_string_returned_unchanged(self) -> None:
        tc = TokenCrypt.from_raw_key(os.urandom(32))
        assert tc.decrypt_if_3ncr("") == ""


class TestIVUniqueness:
    def test_two_encrypts_differ(self) -> None:
        tc = TokenCrypt.from_raw_key(os.urandom(32))
        a = tc.encrypt_3ncr("same plaintext")
        b = tc.encrypt_3ncr("same plaintext")
        assert a != b


class TestTamperDetection:
    def test_flipped_bit_in_payload_is_rejected(self) -> None:
        tc = TokenCrypt.from_raw_key(os.urandom(32))
        enc = tc.encrypt_3ncr("sensitive value")
        # Flip a byte in the middle of the base64 payload.
        body = enc[len(HEADER_V1):]
        idx = len(body) // 2
        flipped = body[:idx] + ("A" if body[idx] != "A" else "B") + body[idx + 1:]
        with pytest.raises(TokenCryptError):
            tc.decrypt_if_3ncr(HEADER_V1 + flipped)

    def test_truncated_payload_is_rejected(self) -> None:
        tc = TokenCrypt.from_raw_key(os.urandom(32))
        with pytest.raises(TokenCryptError):
            tc.decrypt_if_3ncr(HEADER_V1 + "AAAA")


class TestBase64PaddingRobustness:
    def test_decoder_accepts_padded_input(self) -> None:
        # The spec emits no padding, but decoders should accept both.
        tc = TokenCrypt.from_raw_key(CANONICAL_KEY)
        body = CANONICAL_VECTORS[0][1][len(HEADER_V1):]
        padded_body = body + "=" * ((-len(body)) % 4)
        assert tc.decrypt_if_3ncr(HEADER_V1 + padded_body) == CANONICAL_VECTORS[0][0]

    def test_encoder_emits_no_padding(self) -> None:
        tc = TokenCrypt.from_raw_key(os.urandom(32))
        enc = tc.encrypt_3ncr("some value")
        assert "=" not in enc


class TestKDFs:
    def test_raw_key_requires_32_bytes(self) -> None:
        with pytest.raises(ValueError):
            TokenCrypt.from_raw_key(b"\x00" * 31)
        with pytest.raises(ValueError):
            TokenCrypt.from_raw_key(b"\x00" * 33)

    def test_sha3_round_trip(self) -> None:
        tc = TokenCrypt.from_sha3("some-high-entropy-api-token")
        assert tc.decrypt_if_3ncr(tc.encrypt_3ncr("hello")) == "hello"

    def test_argon2id_round_trip(self) -> None:
        tc = TokenCrypt.from_argon2id(
            "correct horse battery staple", b"0123456789abcdef"
        )
        for plaintext, _ in CANONICAL_VECTORS:
            assert tc.decrypt_if_3ncr(tc.encrypt_3ncr(plaintext)) == plaintext

    def test_argon2id_short_salt_rejected(self) -> None:
        with pytest.raises(ValueError):
            TokenCrypt.from_argon2id("secret", b"short")

    def test_argon2id_wrong_secret_fails(self) -> None:
        salt = b"0123456789abcdef"
        tc = TokenCrypt.from_argon2id("right secret", salt)
        enc = tc.encrypt_3ncr("hello")

        other = TokenCrypt.from_argon2id("wrong secret", salt)
        with pytest.raises(TokenCryptError):
            other.decrypt_if_3ncr(enc)
