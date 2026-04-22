"""3ncr.org v1 envelope implementation.

Envelope format: ``3ncr.org/1#<base64(iv[12] || ciphertext || tag[16])>``
using AES-256-GCM and base64 without padding.
"""

from __future__ import annotations

import base64
import hashlib
import os
import warnings
from typing import Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HEADER_V1 = "3ncr.org/1#"

_AES_KEY_SIZE = 32
_IV_SIZE = 12
_TAG_SIZE = 16

# 3ncr.org recommended Argon2id parameters for interoperability
# (see https://3ncr.org/1/ — Key Derivation section).
_ARGON2ID_MEMORY_KIB = 19456
_ARGON2ID_TIME_COST = 2
_ARGON2ID_PARALLELISM = 1
_ARGON2ID_MIN_SALT_BYTES = 16

_BytesLike = Union[str, bytes]


class TokenCryptError(ValueError):
    """Raised when a 3ncr.org value cannot be decoded or decrypted."""


def _as_bytes(value: _BytesLike) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    return value


def _b64encode_no_pad(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii").rstrip("=")


def _b64decode_accept_pad(data: str) -> bytes:
    # Spec emits no padding; decoders accept both for robustness.
    missing = (-len(data)) % 4
    try:
        return base64.b64decode(data + "=" * missing, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise TokenCryptError(f"invalid base64 payload: {exc}") from exc


class TokenCrypt:
    """A 3ncr.org v1 encrypter / decrypter bound to a 32-byte AES key."""

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes")
        if len(key) != _AES_KEY_SIZE:
            raise ValueError(
                f"key must be exactly {_AES_KEY_SIZE} bytes, got {len(key)}"
            )
        self._aesgcm = AESGCM(bytes(key))

    @classmethod
    def from_raw_key(cls, key: bytes) -> "TokenCrypt":
        """Build a TokenCrypt from a raw 32-byte AES-256 key."""
        return cls(key)

    @classmethod
    def from_sha3(cls, secret: _BytesLike) -> "TokenCrypt":
        """Derive the AES key from a high-entropy secret via a single SHA3-256.

        Suitable for random pre-shared keys, UUIDs, or long random API tokens —
        inputs that already carry at least 128 bits of unique entropy.
        """
        return cls(hashlib.sha3_256(_as_bytes(secret)).digest())

    @classmethod
    def from_argon2id(cls, secret: _BytesLike, salt: bytes) -> "TokenCrypt":
        """Derive the AES key from a low-entropy secret via Argon2id.

        Uses the 3ncr.org v1 recommended parameters (m=19456 KiB, t=2, p=1).
        ``salt`` must be at least 16 bytes.
        """
        if not isinstance(salt, (bytes, bytearray)):
            raise TypeError("salt must be bytes")
        if len(salt) < _ARGON2ID_MIN_SALT_BYTES:
            raise ValueError(
                f"salt must be at least {_ARGON2ID_MIN_SALT_BYTES} bytes, got {len(salt)}"
            )
        from argon2.low_level import Type, hash_secret_raw

        key = hash_secret_raw(
            secret=_as_bytes(secret),
            salt=bytes(salt),
            time_cost=_ARGON2ID_TIME_COST,
            memory_cost=_ARGON2ID_MEMORY_KIB,
            parallelism=_ARGON2ID_PARALLELISM,
            hash_len=_AES_KEY_SIZE,
            type=Type.ID,
        )
        return cls(key)

    @classmethod
    def from_pbkdf2_sha3(
        cls, secret: _BytesLike, salt: _BytesLike, iterations: int = 1000
    ) -> "TokenCrypt":
        """Derive the AES key via PBKDF2-SHA3-256 (legacy KDF).

        .. deprecated::
            PBKDF2-SHA3 is retained for backward compatibility with data
            encrypted by earlier versions of 3ncr.org libraries. New callers
            should use :meth:`from_argon2id` (low-entropy secrets) or
            :meth:`from_sha3` / :meth:`from_raw_key` (high-entropy secrets).
            See https://3ncr.org/1/#kdf.
        """
        warnings.warn(
            "from_pbkdf2_sha3 is the legacy 3ncr.org v1 KDF; use from_argon2id "
            "for passwords or from_raw_key/from_sha3 for high-entropy secrets.",
            DeprecationWarning,
            stacklevel=2,
        )
        key = hashlib.pbkdf2_hmac(
            "sha3_256",
            _as_bytes(secret),
            _as_bytes(salt),
            iterations,
            _AES_KEY_SIZE,
        )
        return cls(key)

    def encrypt_3ncr(self, plaintext: str) -> str:
        """Encrypt a UTF-8 string and return a ``3ncr.org/1#...`` value."""
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be a str")
        iv = os.urandom(_IV_SIZE)
        ct_and_tag = self._aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
        return HEADER_V1 + _b64encode_no_pad(iv + ct_and_tag)

    def decrypt_if_3ncr(self, value: str) -> str:
        """Decrypt ``value`` if it has the ``3ncr.org/1#`` header; otherwise
        return it unchanged.

        This is the convenience entry point for passing configuration values
        through regardless of whether they are encrypted.
        """
        if not isinstance(value, str):
            raise TypeError("value must be a str")
        if not value.startswith(HEADER_V1):
            return value
        return self._decrypt(value[len(HEADER_V1):])

    def _decrypt(self, body: str) -> str:
        buf = _b64decode_accept_pad(body)
        if len(buf) < _IV_SIZE + _TAG_SIZE:
            raise TokenCryptError("truncated 3ncr token")
        iv = buf[:_IV_SIZE]
        ct_and_tag = buf[_IV_SIZE:]
        try:
            plaintext = self._aesgcm.decrypt(iv, ct_and_tag, None)
        except InvalidTag as exc:
            raise TokenCryptError("authentication tag verification failed") from exc
        return plaintext.decode("utf-8")
