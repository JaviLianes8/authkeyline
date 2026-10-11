"""Parse and rebuild OpenSSH authorized_keys lines."""

from __future__ import annotations

import re

from ._model import AuthKeyError, AuthorizedKey, KeyOption

_KEY_TYPE_PREFIXES = ("ssh-", "ecdsa-", "sk-")
_BASE64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def parse_line(line: str) -> AuthorizedKey:
    """Parse one authorized_keys line into an :class:`AuthorizedKey`.

    Rejects blank lines, comment lines and anything missing a key type or blob.
    """
    text = line.strip()
    if not text or text.startswith("#"):
        raise AuthKeyError("not an authorized_keys entry")

    first, rest = _split_field(text)
    if _is_key_type(first):
        options: tuple[KeyOption, ...] = ()
        key_type, rest = first, rest
    else:
        options = _parse_options(first)
        key_type, rest = _split_field(rest)

    if not key_type:
        raise AuthKeyError("missing key type")
    blob, comment = _split_field(rest)
    if not blob:
        raise AuthKeyError("missing key blob")
    if not _BASE64.match(blob):
        raise AuthKeyError(f"invalid key blob: {blob!r}")
    return AuthorizedKey(
        key_type=key_type, key_base64=blob, options=options, comment=comment.strip()
    )


def parse_file(text: str) -> list[AuthorizedKey]:
    """Parse every key in a file, skipping blank and ``#`` comment lines."""
    keys: list[AuthorizedKey] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        keys.append(parse_line(stripped))
    return keys


def build_line(key: AuthorizedKey) -> str:
    """Render an :class:`AuthorizedKey` back into one authorized_keys line."""
    fields = []
    if key.options:
        fields.append(",".join(_build_option(option) for option in key.options))
    fields.append(key.key_type)
    fields.append(key.key_base64)
    line = " ".join(fields)
    if key.comment:
        line += " " + key.comment
    return line


def _is_key_type(token: str) -> bool:
    return token.startswith(_KEY_TYPE_PREFIXES)


def _split_field(text: str) -> tuple[str, str]:
    """Split at the first whitespace outside a quoted value."""
    text = text.lstrip()
    in_quote = False
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\" and in_quote:
            escaped = True
            continue
        if char == '"':
            in_quote = not in_quote
            continue
        if not in_quote and char in " \t":
            return text[:index], text[index + 1 :]
    return text, ""


def _parse_options(segment: str) -> tuple[KeyOption, ...]:
    return tuple(_parse_option(part) for part in _split_options(segment) if part)


def _split_options(segment: str) -> list[str]:
    """Split on commas that are not inside a quoted value."""
    parts: list[str] = []
    buffer: list[str] = []
    in_quote = False
    escaped = False
    for char in segment:
        if escaped:
            buffer.append(char)
            escaped = False
            continue
        if char == "\\" and in_quote:
            buffer.append(char)
            escaped = True
            continue
        if char == '"':
            in_quote = not in_quote
            buffer.append(char)
            continue
        if char == "," and not in_quote:
            parts.append("".join(buffer))
            buffer = []
            continue
        buffer.append(char)
    parts.append("".join(buffer))
    return parts


def _parse_option(part: str) -> KeyOption:
    name, sep, raw = part.partition("=")
    if not sep:
        return KeyOption(name)
    return KeyOption(name, _unquote(raw))


def _unquote(raw: str) -> str:
    raw = raw.strip()
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        return raw
    out: list[str] = []
    escaped = False
    for char in raw[1:-1]:
        if escaped:
            out.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            out.append(char)
    return "".join(out)


def _build_option(option: KeyOption) -> str:
    if option.value is None:
        return option.name
    escaped = option.value.replace("\\", "\\\\").replace('"', '\\"')
    return f'{option.name}="{escaped}"'
