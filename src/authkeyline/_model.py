"""Typed records for a single OpenSSH authorized_keys line."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field


class AuthKeyError(ValueError):
    """Raised when a line cannot be read as an authorized_keys entry."""


@dataclass(frozen=True)
class KeyOption:
    """One entry of the leading options field.

    A bare flag (``no-pty``) has ``value`` set to ``None``. A valued option
    (``command="..."``) keeps the already-unquoted text in ``value``.
    """

    name: str
    value: str | None = None


@dataclass(frozen=True)
class AuthorizedKey:
    """A parsed authorized_keys line: options, key type, blob and comment."""

    key_type: str
    key_base64: str
    options: tuple[KeyOption, ...] = ()
    comment: str = field(default="")

    def key_bytes(self) -> bytes:
        """Decode the base64 blob to raw bytes."""
        try:
            return base64.b64decode(self.key_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise AuthKeyError(f"invalid base64 blob: {self.key_base64!r}") from exc
