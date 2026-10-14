"""Parse, check and safely build OpenSSH authorized_keys lines into typed records."""

from __future__ import annotations

from ._codec import LineProblem, build_line, check_file, parse_file, parse_line
from ._errors import AuthKeyError
from ._keytypes import KEY_TYPES as _KEY_TYPES
from ._model import AuthorizedKey, KeyOption
from ._records import Certificate, PublicKey

__version__ = "0.2.0"

KEY_TYPES: frozenset[str] = frozenset(_KEY_TYPES)

__all__ = [
    "KEY_TYPES",
    "AuthKeyError",
    "AuthorizedKey",
    "Certificate",
    "KeyOption",
    "LineProblem",
    "PublicKey",
    "build_line",
    "check_file",
    "parse_file",
    "parse_line",
]
