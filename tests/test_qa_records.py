"""Hand-built records: bounded and secret-free messages, TypeError for wrong fields, plain text."""

from __future__ import annotations

import pickle
import typing
from collections.abc import Callable
from typing import Any

import pytest
from keyfactory import b64, certificate, ed25519_line

import authkeyline
from authkeyline import (
    AuthKeyError,
    AuthorizedKey,
    Certificate,
    KeyOption,
    LineProblem,
    PublicKey,
    build_line,
    check_file,
    parse_line,
)

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"


@pytest.mark.parametrize(
    "key_type", ["x" * 500, "Z" * 500, "ssh-ed25519-" + "q" * 300], ids=["x", "Z", "prefix"]
)
def test_unknown_key_type_of_a_hand_built_record_is_quoted_short(key_type: str) -> None:
    key = AuthorizedKey(key_type, BLOB)
    for call in (key.public_key, key.fingerprint):
        with pytest.raises(AuthKeyError) as caught:
            call()
        assert len(str(caught.value)) < 120 and f"({len(key_type)} characters)" in str(caught.value)


@pytest.mark.parametrize(
    "line",
    [
        f'no-pty, environment="API_TOKEN=ghp_s3cr3tValue" ssh-ed25519 {BLOB}',
        f'no-pty, environment="API_TOKEN=ghp s3cr3tValue" ssh-ed25519 {BLOB}',
        f'no-pty,\tx,environment="API_TOKEN=ghp_s3cr3tValue" ssh-ed25519 {BLOB}',
    ],
    ids=["comma-space", "spaced-value", "comma-tab"],
)
def test_an_option_read_as_key_type_does_not_leak_its_value(line: str) -> None:
    with pytest.raises(AuthKeyError) as caught:
        parse_line(line)
    assert "s3cr3t" not in str(caught.value) and "unsupported key type" in str(caught.value)
    assert all("s3cr3t" not in problem.message for problem in check_file(line))
    hand_built = AuthorizedKey('environment="API_TOKEN=ghp_s3cr3tValue"', BLOB)
    for call in (hand_built.public_key, lambda: build_line(hand_built)):
        with pytest.raises(AuthKeyError) as caught:
            call()
        assert "s3cr3t" not in str(caught.value)


def test_a_plain_unknown_key_type_is_still_quoted() -> None:
    with pytest.raises(AuthKeyError, match="unsupported key type 'ssh-dss'"):
        parse_line(f"no-pty ssh-dss {BLOB}")


WRONG_FIELDS: list[tuple[dict[str, Any], str]] = [
    ({"key_type": 123}, "key_type must be a str, not int"),
    ({"key_type": ["x"]}, "key_type must be a str, not list"),
    ({"key_base64": 123}, "key_base64 must be a str, not int"),
    ({"key_base64": None}, "key_base64 must be a str, not NoneType"),
    ({"key_base64": BLOB.encode()}, "key_base64 must be a str, not bytes"),
    ({"comment": None}, "comment must be a str, not NoneType"),
    ({"options": [KeyOption("no-pty")]}, "options must be a tuple, not list"),
    ({"options": ("no-pty",)}, "options must hold KeyOption items, not str"),
    ({"options": (KeyOption(None),)}, "an option name must be a str"),  # type: ignore[arg-type]
    ({"options": (KeyOption("environment", 5),)}, "an option value must be a str or None"),  # type: ignore[arg-type]
]


@pytest.mark.parametrize(("fields", "message"), WRONG_FIELDS)
def test_every_method_raises_type_error_for_a_field_of_the_wrong_type(
    fields: dict[str, Any], message: str
) -> None:
    key = AuthorizedKey(**{"key_type": "ssh-ed25519", "key_base64": BLOB, **fields})
    calls: list[Callable[[], object]] = [key.public_key, key.fingerprint, key.key_bytes]
    calls.append(key.environment)
    calls += [lambda: key.has_flag("x"), lambda: key.values("x"), lambda: build_line(key)]
    for call in calls:
        with pytest.raises(TypeError, match=message):
            call()


class Lying(str):
    """A str subclass whose comparisons and membership tests lie."""

    __hash__ = str.__hash__

    def __eq__(self, other: object) -> bool:
        return True

    def __contains__(self, item: object) -> bool:
        return False


def test_build_line_reads_str_subclasses_as_plain_text() -> None:
    key = AuthorizedKey("ssh-ed25519", BLOB, (), Lying("x\0 junk"))
    with pytest.raises(AuthKeyError, match="NUL or a line break"):
        build_line(key)
    for options in [(KeyOption(Lying("no-pty")),), (KeyOption("command", Lying("a\nb")),)]:
        with pytest.raises(AuthKeyError):
            build_line(AuthorizedKey("ssh-ed25519", BLOB, options, Lying("c\r")))
    line = build_line(AuthorizedKey(Lying("ssh-ed25519"), Lying(BLOB), (), Lying("ok")))
    assert type(line) is str and line == f"ssh-ed25519 {BLOB} ok"


class Hostile(str):
    """A str subclass whose methods return other text."""

    def removesuffix(self, suffix: str) -> str:
        return "garbage"

    def lower(self) -> str:
        return "no-pty"

    def rstrip(self, chars: str | None = None) -> str:
        return "garbage"


def test_str_subclasses_are_read_as_plain_text() -> None:
    assert parse_line(Hostile(ed25519_line("c"))).comment == "c"
    key = parse_line("restrict " + ed25519_line("c"))
    assert key.has_flag(Hostile("restrict")) and not key.has_flag(Hostile("pty"))
    assert key.values(Hostile("command")) == ()
    hand = AuthorizedKey(Hostile("ssh-ed25519"), Hostile(BLOB), (KeyOption(Hostile("Pty")),))
    assert hand.public_key().bits == 256 and hand.has_flag("pty")


PUBLIC = (AuthKeyError, AuthorizedKey, Certificate, KeyOption, LineProblem, PublicKey)


def test_public_names_report_the_public_module() -> None:
    names = [getattr(authkeyline, name) for name in authkeyline.__all__ if name != "KEY_TYPES"]
    assert {obj.__module__ for obj in names} == {"authkeyline"}
    assert repr(AuthorizedKey) == "<class 'authkeyline.AuthorizedKey'>"


def test_pickles_name_only_the_public_module() -> None:
    key = parse_line('restrict,command="x" ' + ed25519_line("c"))
    cert = parse_line(f"ssh-ed25519-cert-v01@openssh.com {b64(certificate())}").public_key()
    values = [key, key.public_key(), LineProblem(1, "m"), cert, AuthKeyError("x", 1)]
    data = pickle.dumps(values)
    assert b"authkeyline._" not in data and b"authkeyline" in data
    assert pickle.loads(data)[:4] == values[:4]
    assert pickle.dumps(parse_line).find(b"authkeyline._") < 0


@pytest.mark.parametrize("cls", PUBLIC, ids=lambda c: c.__name__)
def test_type_hints_of_public_classes_still_resolve(cls: type[Any]) -> None:
    hints = typing.get_type_hints(cls)
    if cls is Certificate:
        assert hints["ca_key"] is PublicKey and hints["serial"] is int
    if cls is AuthorizedKey:
        assert hints["options"] == tuple[KeyOption, ...]
