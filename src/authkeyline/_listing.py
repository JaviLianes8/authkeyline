"""The text listing of the command line, as ``ssh-keygen -l`` prints each key of a file."""

from __future__ import annotations

import unicodedata

from ._keytypes import KEY_TYPES

_BLANK = " \t"
# What wcwidth() cannot print in a glibc UTF-8 locale: controls, unassigned code points, the
# line and paragraph separators, and bytes that are not UTF-8 (read as lone surrogates).
_UNPRINTABLE = frozenset({"Cc", "Cs", "Cn", "Zl", "Zp"})


def keygen_comment(raw: str) -> str | None:
    """The comment ``ssh-keygen -l`` shows for a line sshd accepts, or None for none.

    do_fingerprint in ssh-keygen.c cuts the line at the first CR, takes the text after the
    blob unless it is empty or starts with ``#``, and otherwise shows the options field.
    """
    text = raw.split("\0", 1)[0].split("\r", 1)[0].lstrip(_BLANK)
    options = None
    if _word(text) not in KEY_TYPES:
        end = _options_end(text)
        options, text = text[:end], text[end:].lstrip(_BLANK)
    rest = text[len(_word(text)) :].lstrip(_BLANK)
    rest = rest[len(_word(rest)) :].lstrip(_BLANK)
    if rest and not rest.startswith("#"):
        return rest
    return options


def escape(text: str) -> str:
    """Escape ``text`` as mprintf does: each byte of an unprintable character as ``\\ooo``."""
    return "".join(
        char
        if char == "\t" or unicodedata.category(char) not in _UNPRINTABLE
        else "".join(f"\\{byte:03o}" for byte in _bytes(char))
        for char in text
    )


def _bytes(char: str) -> bytes:
    if "\udc80" <= char <= "\udcff":
        return bytes([ord(char) - 0xDC00])  # a byte read with surrogateescape
    return char.encode("utf-8", "surrogatepass")


def _word(text: str) -> str:
    end = len(text)
    for blank in _BLANK:
        found = text.find(blank)
        if 0 <= found < end:
            end = found
    return text[:end]


def _options_end(text: str) -> int:
    """Where ssh-keygen's scan of the options field stops: a blank outside double quotes."""
    pos, quoted = 0, False
    while pos < len(text) and (quoted or text[pos] not in _BLANK):
        if text[pos] == "\\" and text[pos + 1 : pos + 2] == '"':
            pos += 1
        elif text[pos] == '"':
            quoted = not quoted
        pos += 1
    return pos
