"""The error type of the library and the helpers that keep its messages short and safe."""

from __future__ import annotations

# A message quotes at most this many characters of any value taken from the input.
SHOWN = 40


class AuthKeyError(ValueError):
    """Raised when text cannot be read, or a record cannot be written, as an authorized_keys entry.

    ``reason`` is the message without a line number. ``line`` is the 1-based line number
    when the error comes from :func:`parse_file`, otherwise ``None``. Messages quote at most
    40 characters of any value and never quote the value of an ``environment`` option.

    >>> from authkeyline import AuthKeyError, parse_file
    >>> try:
    ...     parse_file("# keys\\nno-pty\\n")
    ... except AuthKeyError as error:
    ...     print(error.line, error.reason, isinstance(error, ValueError))
    2 missing key type True
    """

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(message if line is None else f"line {line}: {message}")
        self.reason = message
        self.line = line

    def __reduce__(self) -> tuple[type[AuthKeyError], tuple[str, int | None], dict[str, object]]:
        # The default would rebuild the error from the formatted text and lose ``line``.
        return type(self), (self.reason, self.line), self.__dict__


def shown(text: str) -> str:
    """``repr`` of at most 40 characters of ``text``, with the full length when cut."""
    if len(text) <= SHOWN:
        return repr(text)
    return f"{text[:SHOWN]!r}... ({len(text)} characters)"


def type_name(value: object) -> str:
    """The name of the type of ``value``, cut to 40 characters."""
    name = type(value).__name__
    return name if len(name) <= SHOWN else name[:SHOWN] + "..."


def require_str(value: object, what: str) -> str:
    """Return ``value`` as a plain ``str``; raise TypeError when it is not text."""
    if not isinstance(value, str):
        raise TypeError(f"{what} must be a str, not {type_name(value)}")
    # A str subclass could change how methods behave; the library works on plain text.
    return str.__str__(value)
