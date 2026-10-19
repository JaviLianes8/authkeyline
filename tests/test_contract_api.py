"""The complete promise of every public name: signature, fields, result and failure types."""

from __future__ import annotations

import dataclasses
import doctest
import inspect
import pickle
from typing import Any

import pytest
from keyfactory import ed25519_line

import authkeyline
from authkeyline import (
    KEY_TYPES,
    AuthKeyError,
    AuthorizedKey,
    Certificate,
    KeyOption,
    LineProblem,
    PublicKey,
    build_line,
    check_file,
    parse_file,
    parse_line,
)

SIGNATURES = {
    parse_line: "(line: 'str') -> 'AuthorizedKey'",
    parse_file: "(text: 'str') -> 'list[AuthorizedKey]'",
    check_file: "(text: 'str') -> 'list[LineProblem]'",
    build_line: "(key: 'AuthorizedKey') -> 'str'",
    AuthorizedKey.fingerprint: "(self, hash: \"Literal['sha256', 'md5']\" = 'sha256') -> 'str'",
    PublicKey.fingerprint: "(self, hash: \"Literal['sha256', 'md5']\" = 'sha256') -> 'str'",
    AuthorizedKey.values: "(self, name: 'str') -> 'tuple[str, ...]'",
    AuthorizedKey.has_flag: "(self, name: 'str') -> 'bool'",
    AuthorizedKey.environment: "(self) -> 'dict[str, str]'",
    AuthorizedKey.public_key: "(self) -> 'PublicKey'",
    AuthorizedKey.key_bytes: "(self) -> 'bytes'",
    AuthKeyError: "(message: 'str', line: 'int | None' = None) -> 'None'",
}
FIELDS: dict[type[Any], list[tuple[str, object]]] = {
    AuthorizedKey: [("key_type", ...), ("key_base64", ...), ("options", ()), ("comment", "")],
    KeyOption: [("name", ...), ("value", None)],
    LineProblem: [("line", ...), ("message", ...)],
    PublicKey: [
        *[(name, ...) for name in ("key_type", "short_type", "bits", "blob", "plain_blob")],
        *[("application", None), ("certificate", None)],
    ],
    Certificate: [
        (name, ...)
        for name in [
            *("cert_type", "serial", "key_id", "principals", "valid_after", "valid_before"),
            *("critical_options", "extensions", "ca_key", "signature_type"),
        ]
    ],
}


@pytest.mark.parametrize("target", list(SIGNATURES), ids=lambda t: t.__qualname__)
def test_signatures_are_pinned(target: Any) -> None:
    assert str(inspect.signature(target)) == SIGNATURES[target]


@pytest.mark.parametrize("cls", list(FIELDS), ids=lambda c: c.__name__)
def test_records_are_frozen_dataclasses_with_pinned_fields(cls: type[Any]) -> None:
    found = [
        (f.name, ... if f.default is dataclasses.MISSING else f.default)
        for f in dataclasses.fields(cls)
    ]
    assert found == FIELDS[cls]
    assert cls.__dataclass_params__.frozen


def test_records_compare_hash_and_pickle_by_value() -> None:
    key = parse_line('restrict,command="x" ' + ed25519_line("c"))
    public = key.public_key()
    for value in (key, key.options[1], public, LineProblem(3, "m")):
        copy = pickle.loads(pickle.dumps(value))
        assert copy == value and hash(copy) == hash(value)
        with pytest.raises(dataclasses.FrozenInstanceError):
            value.line = 1  # type: ignore[misc,union-attr]


def test_key_types_is_a_frozen_set_of_names() -> None:
    assert isinstance(KEY_TYPES, frozenset) and len(KEY_TYPES) == 22
    assert all(isinstance(name, str) and " " not in name for name in KEY_TYPES)


def test_error_is_a_value_error_with_reason_and_line() -> None:
    error = AuthKeyError("bad", 7)
    assert isinstance(error, ValueError)
    assert (str(error), error.reason, error.line) == ("line 7: bad", "bad", 7)
    copy = pickle.loads(pickle.dumps(error))
    assert (str(copy), copy.reason, copy.line) == ("line 7: bad", "bad", 7)
    assert (str(AuthKeyError("x")), AuthKeyError("x").line) == ("x", None)


@pytest.mark.parametrize("wrong", [None, b"x", 1, ["x"]])
def test_text_functions_refuse_what_is_not_text(wrong: Any) -> None:
    for call in (parse_line, parse_file, check_file):
        with pytest.raises(TypeError, match="must be a str"):
            call(wrong)


def test_query_methods_refuse_what_is_not_text() -> None:
    key = parse_line(ed25519_line())
    calls: list[Any] = [key.values, key.has_flag, key.fingerprint, key.public_key().fingerprint]
    for call in calls:
        with pytest.raises(TypeError, match="must be a str"):
            call(1)
    with pytest.raises(AuthKeyError, match=r"\(10000 characters\)"):
        key.fingerprint("x" * 10_000)  # type: ignore[arg-type]


def _built(**changes: Any) -> None:
    key = parse_line(ed25519_line("c"))
    build_line(dataclasses.replace(key, **changes))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"key_type": None}, "key_type must be a str"),
        ({"key_base64": 1}, "key_base64 must be a str"),
        ({"comment": b"x"}, "comment must be a str"),
        ({"options": [KeyOption("restrict")]}, "options must be a tuple"),
        ({"options": ("restrict",)}, "must hold KeyOption items"),
        ({"options": (KeyOption(None),)}, "option name must be a str"),  # type: ignore[arg-type]
        ({"options": (KeyOption("command", 5),)}, "option value must be a str or None"),  # type: ignore[arg-type]
    ],
)
def test_build_line_refuses_fields_of_the_wrong_type(changes: Any, message: str) -> None:
    with pytest.raises(TypeError, match=message):
        _built(**changes)
    with pytest.raises(TypeError, match="must be an AuthorizedKey"):
        build_line("ssh-ed25519 AAAA")  # type: ignore[arg-type]


def test_every_public_name_has_a_runnable_example() -> None:
    finder = doctest.DocTestFinder()
    objects = [authkeyline, *(getattr(authkeyline, name) for name in authkeyline.__all__)]
    objects += [AuthorizedKey.public_key, AuthorizedKey.values, AuthorizedKey.fingerprint]
    objects += [AuthorizedKey.environment, AuthorizedKey.key_bytes, PublicKey.fingerprint]
    for target in objects:
        if target is KEY_TYPES:
            continue  # shown in the package docstring
        found = finder.find(target, getattr(target, "__name__", None), module=False, globs={})
        assert any(test.examples for test in found), target
