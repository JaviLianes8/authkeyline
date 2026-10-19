"""The line-level key checks of sshkey_read."""

from __future__ import annotations

from ._errors import AuthKeyError, shown, unsupported_type
from ._keytypes import KEY_TYPES


def check_type_agrees(line_type: str, blob_type: str) -> None:
    """sshd compares the key type, and the curve for ECDSA, not the exact name."""
    line_kind = KEY_TYPES.get(line_type)
    if line_kind is None:
        raise unsupported_type(line_type)
    if line_kind.identity != KEY_TYPES[blob_type].identity:
        raise AuthKeyError(
            f"line says {shown(line_type)} but the key blob holds {shown(blob_type)}"
        )
