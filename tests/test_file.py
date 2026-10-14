"""Whole files: blanks and comments skipped, problems reported with their line number."""

from __future__ import annotations

import pytest
from keyfactory import ed25519_line

from authkeyline import AuthKeyError, LineProblem, check_file, parse_file

ONE, TWO = ed25519_line("one"), ed25519_line("two")


def test_parse_file_skips_blanks_and_comments() -> None:
    text = f"\n# a comment\n{ONE}\n\n  \t# indented comment\r\n \t \n{TWO}\r\n"
    assert [key.comment for key in parse_file(text)] == ["one", "two"]


def test_parse_file_names_the_failing_line() -> None:
    with pytest.raises(AuthKeyError) as caught:
        parse_file(f"{ONE}\n# c\nno-pty ssh-ed25519 AAAA\n{TWO}\n")
    assert caught.value.line == 3
    assert str(caught.value).startswith("line 3: ")
    assert caught.value.reason == str(caught.value)[len("line 3: ") :]


def test_check_file_lists_every_problem() -> None:
    text = f"{ONE}\nbogus {TWO}\n\nssh-ed25519\n#x\n{TWO}"
    assert check_file(text) == [
        LineProblem(2, "unknown option 'bogus'"),
        LineProblem(4, "missing key blob"),
    ]
    assert check_file(f"{ONE}\n{TWO}\n") == []


def test_error_without_a_line_number() -> None:
    error = AuthKeyError("plain")
    assert (error.line, error.reason, str(error)) == (None, "plain", "plain")
    assert isinstance(error, ValueError)
