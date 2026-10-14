"""The single error type of the library."""

from __future__ import annotations


class AuthKeyError(ValueError):
    """Raised when text cannot be read, or a record cannot be written, as an authorized_keys entry.

    ``line`` holds the 1-based line number when the error comes from a whole file.
    """

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(message if line is None else f"line {line}: {message}")
        self.reason = message
        self.line = line
