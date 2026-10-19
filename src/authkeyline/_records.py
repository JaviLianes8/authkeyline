"""Typed views of a decoded public key and of an OpenSSH certificate."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Literal

from ._errors import AuthKeyError, require_str, shown


@dataclass(frozen=True)
class Certificate:
    """The body of an OpenSSH certificate (draft-miller-ssh-cert).

    The signature type is checked against the CA key, but the signature itself is not
    verified: sshd verifies it and skips the line when it does not match. ``valid_after``
    and ``valid_before`` are seconds since the epoch as stored (``2**64 - 1`` means
    forever); names in ``critical_options`` and ``extensions`` are decoded as UTF-8 with
    replacement characters, their data is kept as bytes.

    A user certificate made by ``ssh-keygen -s ca -I ops -n alice,deploy -z 42 -O no-pty
    -V 20260101:20270101`` in a UTC+1 time zone:

    >>> from authkeyline import parse_line
    >>> CERT = (
    ...     "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAID3LNIznOTTtPTL1hifu6/lv"
    ...     "o3nodKco4p6fV3o2/X3lAAAAICYYF7hxl27cutEQ1KktLE/aVte2L+s+oAsVjUSemf8SAAAAAAAA"
    ...     "ACoAAAABAAAAA29wcwAAABMAAAAFYWxpY2UAAAAGZGVwbG95AAAAAGlVqvAAAAAAazbecAAAAAAA"
    ...     "AABwAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRp"
    ...     "bmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAA"
    ...     "AAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIANH+9lif02j2QtkQmCFjW4yDpzTUG7VSsdtftWq"
    ...     "305CAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEB6Fa3Rt3+JV6L/cwzjDmsR4VX5U5MnaRedjSv5RnTJ"
    ...     "9fR73dtckNlUl8uBIXXqqC0DjcBxmUIkN7hAUDUowY8A"
    ... )
    >>> cert = parse_line(f"ssh-ed25519-cert-v01@openssh.com {CERT}").public_key().certificate
    >>> cert.cert_type, cert.serial, cert.key_id, cert.principals
    ('user', 42, 'ops', ('alice', 'deploy'))
    >>> cert.valid_after, cert.valid_before
    (1767222000, 1798758000)
    >>> [name for name, _ in cert.extensions][:2], cert.signature_type
    (['permit-X11-forwarding', 'permit-agent-forwarding'], 'ssh-ed25519')
    >>> cert.ca_key.fingerprint()
    'SHA256:6gjYs61ByrFQyriT+wR0tdohG9Az4NmoWfFuu3GbE+I'
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
    (``ED25519``, ``RSA-CERT``), ``bits`` the size ssh-keygen prints. ``blob`` is the whole
    decoded blob as written on the line; ``plain_blob`` is the blob of the bare key that a
    fingerprint is computed over, also for a certificate.
    ``application`` is the security key application (``ssh:`` by default) of the ``sk-``
    types, ``certificate`` the body of a certificate; both are ``None`` otherwise.

    >>> from authkeyline import parse_line
    >>> blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
    >>> key = parse_line(f"ssh-ed25519 {blob}").public_key()
    >>> key.key_type, key.short_type, key.bits, key.application, key.certificate
    ('ssh-ed25519', 'ED25519', 256, None, None)
    """

    key_type: str
    short_type: str
    bits: int
    blob: bytes
    plain_blob: bytes
    application: str | None = None
    certificate: Certificate | None = None

    def fingerprint(self, hash: Literal["sha256", "md5"] = "sha256") -> str:
        """The fingerprint as ``ssh-keygen -l -E <hash>`` prints it.

        Raises :class:`AuthKeyError` for a hash other than ``"sha256"`` or ``"md5"`` and
        ``TypeError`` when ``hash`` is not a ``str``.

        >>> from authkeyline import parse_line
        >>> blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
        >>> parse_line(f"ssh-ed25519 {blob}").public_key().fingerprint("md5")
        'MD5:0f:a2:0a:d7:38:3e:65:45:08:6b:63:84:1c:ff:dc:ba'
        """
        if require_str(hash, "hash") == "sha256":
            digest = hashlib.sha256(self.plain_blob).digest()
            return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
        if hash == "md5":
            digest = hashlib.md5(self.plain_blob, usedforsecurity=False).digest()
            return "MD5:" + ":".join(f"{byte:02x}" for byte in digest)
        raise AuthKeyError(f"unknown fingerprint hash {shown(hash)}, use 'sha256' or 'md5'")
