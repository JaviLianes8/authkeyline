"""Typed views of a decoded public key and of an OpenSSH certificate."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Literal

from ._errors import AuthKeyError


@dataclass(frozen=True)
class Certificate:
    """The body of an OpenSSH certificate (draft-miller-ssh-cert).

    The signature type is checked against the CA key, but the signature itself is not
    verified: sshd verifies it and skips the line when it does not match.
    """

    cert_type: Literal["user", "host"]
    serial: int
    key_id: str
    principals: tuple[str, ...]
    valid_after: int
    valid_before: int
    critical_options: tuple[tuple[str, bytes], ...]
    extensions: tuple[tuple[str, bytes], ...]
    ca_key: PublicKey
    signature_type: str


@dataclass(frozen=True)
class PublicKey:
    """A decoded key blob.

    ``key_type`` is the name inside the blob, ``short_type`` the label ssh-keygen prints
    (``ED25519``, ``RSA-CERT``), ``bits`` the size ssh-keygen prints. ``plain_blob`` is the
    blob of the bare key that a fingerprint is computed over, also for a certificate.
    """

    key_type: str
    short_type: str
    bits: int
    blob: bytes
    plain_blob: bytes
    application: str | None = None
    certificate: Certificate | None = None

    def fingerprint(self, hash: Literal["sha256", "md5"] = "sha256") -> str:
        """The fingerprint as ``ssh-keygen -l -E <hash>`` prints it."""
        if hash == "sha256":
            digest = hashlib.sha256(self.plain_blob).digest()
            return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
        if hash == "md5":
            digest = hashlib.md5(self.plain_blob, usedforsecurity=False).digest()
            return "MD5:" + ":".join(f"{byte:02x}" for byte in digest)
        raise AuthKeyError(f"unknown fingerprint hash {hash!r}, use 'sha256' or 'md5'")
