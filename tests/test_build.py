"""build_line writes only what sshd reads back as the same record."""

from __future__ import annotations

import dataclasses
import random

import pytest
from keyfactory import ed25519_line

from authkeyline import AuthKeyError, AuthorizedKey, KeyOption, build_line, parse_line

BASE = parse_line(ed25519_line("user@host"))


def with_options(*options: KeyOption, comment: str = "user@host") -> AuthorizedKey:
    return dataclasses.replace(BASE, options=options, comment=comment)


def test_round_trip_of_a_parsed_line() -> None:
    line = f'restrict,command="dump /home",from="10.0.0.1,10.0.0.2" {ed25519_line("u@h")}'
    assert build_line(parse_line(line)) == line


def test_quotes_are_escaped_and_backslashes_kept() -> None:
    key = with_options(KeyOption("command", 'echo "a\\b" \\"x'))
    line = build_line(key)
    assert line.startswith('command="echo \\"a\\b\\" \\\\"x" ssh-ed25519 ')
    assert parse_line(line) == key


def test_without_options_or_comment() -> None:
    key = with_options(comment="")
    assert build_line(key) == f"ssh-ed25519 {BASE.key_base64}"


@pytest.mark.parametrize(
    ("option", "message"),
    [
        (KeyOption('no-pty,command="evil"'), "is not a flag option"),
        (KeyOption("no-pty x"), "is not a flag option"),
        (KeyOption("bogus"), "is not a flag option"),
        (KeyOption("command"), "is not a flag option"),
        (KeyOption("no-pty", "x"), "is not a valued option"),
        (KeyOption("command,no-pty", "x"), "is not a valued option"),
        (KeyOption("command", "a\\"), "ends with a backslash"),
        (KeyOption("command", "a\nssh-ed25519 AAAA"), "line break"),
        (KeyOption("command", "a\rb"), "line break"),
        (KeyOption("command", "a\0b"), "NUL"),
        (KeyOption("environment", "bad name=1"), "environment name"),
        (KeyOption("permitopen", "nohost"), "permitopen"),
    ],
)
def test_options_that_could_inject_or_would_not_read_back(option: KeyOption, message: str) -> None:
    with pytest.raises(AuthKeyError, match=message):
        build_line(with_options(option))


@pytest.mark.parametrize("comment", ["a\nssh-ed25519 AAAA", "a\r", "a\0"])
def test_comment_cannot_break_the_line(comment: str) -> None:
    with pytest.raises(AuthKeyError, match="comment holds"):
        build_line(with_options(comment=comment))


@pytest.mark.parametrize("comment", [" lead", "trail ", "\tx"])
def test_comment_that_would_not_read_back(comment: str) -> None:
    with pytest.raises(AuthKeyError, match="does not read back"):
        build_line(with_options(comment=comment))


def test_key_type_and_blob_are_checked() -> None:
    with pytest.raises(AuthKeyError, match="unsupported key type"):
        build_line(dataclasses.replace(BASE, key_type="ssh-ed25519 x"))
    with pytest.raises(AuthKeyError, match="holds"):
        build_line(dataclasses.replace(BASE, key_type="ssh-rsa"))
    with pytest.raises(AuthKeyError, match="one base64 word"):
        build_line(dataclasses.replace(BASE, key_base64="AAAA AAAA"))


def test_duplicate_single_options_are_refused() -> None:
    with pytest.raises(AuthKeyError, match="more than once"):
        build_line(with_options(KeyOption("command", "a"), KeyOption("Command", "b")))


def test_random_values_round_trip_or_are_refused() -> None:
    """Seeded property: a built line always parses back to the record it came from."""
    rng = random.Random(20261014)
    alphabet = 'ab ,="\\\t#é'
    built = 0
    for _ in range(3000):
        value = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 8)))
        comment = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 6)))
        key = with_options(KeyOption("command", value), KeyOption("no-pty"), comment=comment)
        try:
            line = build_line(key)
        except AuthKeyError:
            assert value.endswith("\\") or comment != comment.strip(" \t")
            continue
        assert parse_line(line) == key
        assert "\n" not in line
        built += 1
    assert built > 1500


def test_blob_that_is_not_a_key() -> None:
    with pytest.raises(AuthKeyError, match="not valid base64"):
        build_line(dataclasses.replace(BASE, key_base64="AAAAA"))
