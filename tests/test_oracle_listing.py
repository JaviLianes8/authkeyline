"""ssh-keygen as the oracle for the comment column of the listing and for its escaping.

Runs only when ``ssh-keygen`` is on the PATH, or AUTHKEYLINE_SSH_KEYGEN names one.
"""

from __future__ import annotations

import contextlib
import io
from pathlib import Path

import pytest
from test_oracle import KEYGEN, keygen, listing

from authkeyline._cli import main

pytestmark = pytest.mark.skipif(KEYGEN is None, reason="ssh-keygen is not on the PATH")

# Lines whose comment column ssh-keygen -l works out in its own way (do_fingerprint): the
# options field stands in for a missing comment, a comment starting with # is ignored,
# trailing blanks stay. The escaped ones need a build that prints through mprintf.
COLUMN_LINES = [
    "no-pty {key}",
    'restrict,command="a b" {key}',
    'command="x \\" y" {key} c',
    "{key} #note",
    "no-pty {key} #note",
    "{key} tail  ",
    "{key} a\tb",
    "{tabbed}\tmy comment",
    "no-pty\t{tabbed}",
]
ESCAPED_LINES = [
    "{key} esc\x1b[31mred\x07\x7f",
    "{key} c\x0bd \x85 caf\u00e9 \u20ac",
    "{key} a\rb",
]


def _escapes(path: Path) -> bool:
    """Whether this ssh-keygen escapes control bytes; the Windows port writes them raw."""
    path.write_bytes(f"{_KEY} a\x1bb\n".encode())
    return b"\\033" in keygen("-l", "-f", path, env=UTF8, binary=True).stdout


UTF8 = {"LC_ALL": "C.UTF-8"}
_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"


def test_comment_column_matches_ssh_keygen(tmp_path: Path) -> None:
    escapes = _escapes(tmp_path / "probe")
    lines = COLUMN_LINES + (ESCAPED_LINES if escapes else [])
    tabbed = _KEY.replace(" ", "\t")
    raw = "\n".join(line.format(key=_KEY, tabbed=tabbed) for line in lines).encode() + b"\n"
    if escapes:
        raw += _KEY.encode() + b" caf\xe9 \xff\n"
    path = tmp_path / "column"
    path.write_bytes(raw)
    expected = keygen("-l", "-f", path, env=UTF8, binary=True)
    assert expected.returncode == 0 and expected.stdout.count(b"\n") == raw.count(b"\n")
    out = io.BytesIO()
    with contextlib.redirect_stdout(io.TextIOWrapper(out, encoding="utf-8")) as stream:
        assert main([str(path)]) == 0
        stream.flush()
    # The Windows port ends its lines with CRLF.
    assert out.getvalue() == expected.stdout.replace(b"\r\n", b"\n")


def test_lines_ssh_keygen_cannot_read_are_still_listed(tmp_path: Path) -> None:
    # Two blanks after the options: sshd uses the key, ssh-keygen -l skips the line.
    path = tmp_path / "double"
    path.write_text(f"{_KEY} first\nno-pty  {_KEY} second\n")
    assert keygen("-l", "-f", path).stdout.count("\n") == 1
    assert listing(path, "sha256").count("\n") == 2
