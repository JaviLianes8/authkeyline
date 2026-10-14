"""Parse, check and rebuild OpenSSH authorized_keys lines."""

from __future__ import annotations

from dataclasses import dataclass

from ._errors import AuthKeyError
from ._keytypes import KEY_TYPES
from ._model import AuthorizedKey, KeyOption
from ._options import read_options
from ._optrules import VALUED, flag_name

_BLANK = " \t"


@dataclass(frozen=True)
class LineProblem:
    """A line of a file that sshd would not use, with the reason."""

    line: int
    message: str


def parse_line(line: str) -> AuthorizedKey:
    """Parse one authorized_keys line, checking it the way sshd does.

    Certificate signatures are the one thing not verified (that needs a crypto library);
    see :class:`Certificate`.

    Raises :class:`AuthKeyError` for blank and comment lines, unknown or malformed options,
    unknown key types, and blobs that do not decode to a key of the stated type.
    """
    text = line.removesuffix("\n")
    if "\n" in text:
        raise AuthKeyError("text holds more than one line")
    # sshd works on C strings: a NUL ends the line; the comment is never looked at.
    text = text.split("\0", 1)[0].lstrip(_BLANK).rstrip(" \t\r")
    if not text or text.startswith("#"):
        raise AuthKeyError("not an authorized_keys entry")
    options: tuple[KeyOption, ...] = ()
    if _first_field(text) not in KEY_TYPES:
        options, end = read_options(text)
        text = text[end:].lstrip(_BLANK)
    key_type = _first_field(text)
    if not key_type:
        raise AuthKeyError("missing key type")
    if key_type not in KEY_TYPES:
        raise AuthKeyError(f"unsupported key type {key_type!r}")
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
    """
    keys: list[AuthorizedKey] = []
    for number, raw in _entries(text):
        try:
            keys.append(parse_line(raw))
        except AuthKeyError as exc:
            raise AuthKeyError(exc.reason, number) from None
    return keys


def check_file(text: str) -> list[LineProblem]:
    """Every line that sshd would skip as broken, in order; an empty list means clean.

    A certificate whose signature does not verify is not caught, see :func:`parse_line`.
    """
    problems: list[LineProblem] = []
    for number, raw in _entries(text):
        try:
            parse_line(raw)
        except AuthKeyError as exc:
            problems.append(LineProblem(number, exc.reason))
    return problems


def build_line(key: AuthorizedKey) -> str:
    """Render an :class:`AuthorizedKey` as one line, refusing anything that would not read back.

    Option names must be known flags or valued options, values cannot hold NUL, CR or LF or
    end with a backslash, the comment cannot hold them either (sshd would cut or ignore
    them, so a written line keeps to plain text), and the result must parse back to the
    same record.
    """
    if key.key_type not in KEY_TYPES:
        raise AuthKeyError(f"unsupported key type {key.key_type!r}")
    if not key.key_base64 or any(char in key.key_base64 for char in " \t\r\n\0"):
        raise AuthKeyError("key blob must be one base64 word")
    fields = []
    if key.options:
        fields.append(",".join(_build_option(option) for option in key.options))
    fields += [key.key_type, key.key_base64]
    if key.comment:
        if any(char in key.comment for char in "\0\r\n"):
            raise AuthKeyError("comment holds a NUL or a line break")
        fields.append(key.comment)
    line = " ".join(fields)
    if parse_line(line) != key:
        raise AuthKeyError("the record does not read back the same; check the fields' spacing")
    return line


def _build_option(option: KeyOption) -> str:
    name = option.name
    if option.value is None:
        if flag_name(name) is None:
            raise AuthKeyError(f"{name!r} is not a flag option")
        return name
    if name.lower() not in VALUED:
        raise AuthKeyError(f"{name!r} is not a valued option")
    value = option.value
    if any(char in value for char in "\0\r\n"):
        raise AuthKeyError(f"value of {name!r} holds a NUL or a line break")
    if value.endswith("\\"):
        raise AuthKeyError(f"value of {name!r} ends with a backslash, which sshd cannot read")
    return name + '="' + value.replace('"', '\\"') + '"'


def _first_field(text: str) -> str:
    for index, char in enumerate(text):
        if char in _BLANK:
            return text[:index]
    return text


def _entries(text: str) -> list[tuple[int, str]]:
    entries = []
    for number, raw in enumerate(text.split("\n"), start=1):
        stripped = raw.lstrip(_BLANK)
        if stripped.strip() and not stripped.startswith("#"):
            entries.append((number, raw))
    return entries
