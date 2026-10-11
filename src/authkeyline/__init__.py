"""Parse and rebuild OpenSSH authorized_keys lines into typed records."""

from __future__ import annotations

from ._codec import build_line, parse_file, parse_line
from ._model import AuthKeyError, AuthorizedKey, KeyOption

__version__ = "0.1.0"

__all__ = [
    "AuthKeyError",
    "AuthorizedKey",
    "KeyOption",
    "build_line",
    "parse_file",
    "parse_line",
]
