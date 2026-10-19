"""Parse, check and rebuild OpenSSH authorized_keys lines."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ._errors import AuthKeyError, require_str, unsupported_type
from ._keytypes import KEY_TYPES
from ._model import AuthorizedKey, KeyOption
from ._options import read_options

_BLANK = " \t"
_FIELD_END = re.compile("[ \t]")
# isspace() in the C locale: a line holding nothing else is blank.
_C_SPACE = " \t\n\v\f\r"
_OPTION_MARKS = frozenset('=",')
_BASE64 = re.compile("[A-Za-z0-9+/]+={0,2}")


@dataclass(frozen=True)
class LineProblem:
    """A line of a file that sshd would not use, with the reason.

    >>> from authkeyline import LineProblem, check_file
    >>> check_file("no-pty\\n") == [LineProblem(line=1, message="missing key type")]
    True
    """

    line: int
    message: str


def parse_line(line: str) -> AuthorizedKey:
    """Parse one authorized_keys line, checking it the way sshd does.

    A final newline is allowed; the line ends at a NUL, as sshd reads C strings.
    Certificate signatures are the one thing not verified (that needs a crypto library);
    see :class:`Certificate`. Raises :class:`AuthKeyError` for blank and comment lines,
    unknown or malformed options, unknown key types, and blobs that do not decode to a key
    of the stated type; ``TypeError`` when ``line`` is not a ``str``.

    >>> from authkeyline import parse_line
    >>> blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
    >>> key = parse_line(f'no-pty,command="uptime" ssh-ed25519 {blob} ops@host')
    >>> key.key_type, key.comment, key.values("command")
    ('ssh-ed25519', 'ops@host', ('uptime',))
    """
    text = require_str(line, "line").removesuffix("\n")
    if "\n" in text:
        raise AuthKeyError("text holds more than one line")
    text = _content(text)
    if not text.strip(_C_SPACE) or text.startswith("#"):
        raise AuthKeyError("not an authorized_keys entry")
    text = text.rstrip(" \t\r")
    options: tuple[KeyOption, ...] = ()
    if _first_field(text) not in KEY_TYPES:
        try:
            options, end = read_options(text)
        except AuthKeyError:
            _refuse_as_key_type(text)
            raise
        text = text[end:].lstrip(_BLANK)
    key_type = _first_field(text)
    if not key_type:
        raise AuthKeyError("missing key type")
    if key_type not in KEY_TYPES:
        raise unsupported_type(key_type)
    rest = text[len(key_type) :].lstrip(_BLANK)
    blob = _first_field(rest)
    if not blob:
        raise AuthKeyError("missing key blob")
    comment = rest[len(blob) :].lstrip(_BLANK)
    key = AuthorizedKey(key_type=key_type, key_base64=blob, options=options, comment=comment)
    key.public_key()
    return key


def parse_file(text: str) -> list[AuthorizedKey]:
    """Parse every key in a file, skipping blank and ``#`` comment lines.

    The first bad line raises :class:`AuthKeyError` with its ``line`` number set.

    >>> from authkeyline import parse_file
    >>> blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
    >>> [key.comment for key in parse_file(f"# team\\n\\nssh-ed25519 {blob} ana\\n")]
    ['ana']
    """
    keys: list[AuthorizedKey] = []
    for number, raw in entries(require_str(text, "text")):
        try:
            keys.append(parse_line(raw))
        except AuthKeyError as exc:
            raise AuthKeyError(exc.reason, number) from None
    return keys


def check_file(text: str) -> list[LineProblem]:
    """Every line that sshd would skip as broken, in order; an empty list means clean.

    A certificate whose signature does not verify is not caught, see :func:`parse_line`.

    >>> from authkeyline import check_file
    >>> blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
    >>> check_file(f"ssh-ed25519 {blob}\\nbogus ssh-ed25519 {blob}\\n")
    [LineProblem(line=2, message="unknown option 'bogus'")]
    """
    problems: list[LineProblem] = []
    for number, raw in entries(require_str(text, "text")):
        try:
            parse_line(raw)
        except AuthKeyError as exc:
            problems.append(LineProblem(number, exc.reason))
    return problems


def _content(line: str) -> str:
    """The part of a line sshd looks at: up to a NUL, after leading spaces and tabs."""
    return line.split("\0", 1)[0].lstrip(_BLANK)


def _refuse_as_key_type(text: str) -> None:
    """Name an unknown key type (``ssh-dss BLOB``) as one, not as an unknown option.

    sshd reads such a word as an option and refuses the line either way; only the reason
    changes. A word holding ``=``, ``"`` or ``,`` is an options field and is left to it.
    """
    word = _first_field(text)
    blob = _first_field(text[len(word) :].lstrip(_BLANK))
    if not _OPTION_MARKS.intersection(word) and _BASE64.fullmatch(blob):
        raise unsupported_type(word)


def _first_field(text: str) -> str:
    end = _FIELD_END.search(text)
    return text if end is None else text[: end.start()]


def entries(text: str) -> list[tuple[int, str]]:
    """The numbered lines of a file that are neither blank nor ``#`` comments."""
    found = []
    for number, raw in enumerate(text.split("\n"), start=1):
        content = _content(raw)
        if content.strip(_C_SPACE) and not content.startswith("#"):
            found.append((number, raw))
    return found
