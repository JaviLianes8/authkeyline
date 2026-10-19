"""Round 2 contracts: what error messages quote, plain text and the published module names."""

from __future__ import annotations

import pickle

import pytest
from keyfactory import b64, certificate, fields

import authkeyline
from authkeyline import AuthKeyError, AuthorizedKey, KeyOption, build_line, check_file, parse_line

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
SK_CERT = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"


@pytest.mark.parametrize(
    "line",
    [
        f'ssh-ed25519 environment="API_TOKEN=ghp_s3cr3tValue" {BLOB}',
        f"ssh-ed25519 environment=API_TOKEN=ghp_s3cr3tValue {BLOB}",
        f'ssh-ed25519 "ghp_s3cr3tValue" {BLOB}',
        'ssh-ed25519 environment="API_TOKEN=ghp_s3cr3tValue"',
    ],
    ids=["quoted", "unquoted", "quote-only", "no-blob"],
)
def test_an_option_read_as_key_blob_does_not_leak_its_value(line: str) -> None:
    with pytest.raises(AuthKeyError) as caught:
        parse_line(line)
    assert "s3cr3t" not in str(caught.value) and "key blob is not" in str(caught.value)
    assert all("s3cr3t" not in problem.message for problem in check_file(line))
    hand_built = AuthorizedKey("ssh-ed25519", line.split(" ")[1])
    for call in (hand_built.public_key, hand_built.key_bytes):
        with pytest.raises(AuthKeyError) as caught:
            call()
        assert "s3cr3t" not in str(caught.value)


@pytest.mark.parametrize(
    ("blob", "message"),
    [
        ("AAAA!x", "key blob is not valid base64: 'AAAA!x'"),
        ("AAB=", "key blob is not canonical base64: 'AAB='"),
        ("AAAAC3Nz=", "key blob is not valid base64: 'AAAAC3Nz='"),
    ],
)
def test_a_blob_that_is_not_option_like_is_still_quoted(blob: str, message: str) -> None:
    with pytest.raises(AuthKeyError) as caught:
        parse_line(f"ssh-ed25519 {blob}")
    assert caught.value.reason == message


@pytest.mark.parametrize(
    "line",
    [
        f"restrict environment=TOKEN=s3cret ssh-ed25519 {BLOB}",
        f'restrict "s3cret" ssh-ed25519 {BLOB}',
    ],
    ids=["equals-only", "quote-only"],
)
def test_an_option_like_key_type_is_never_quoted(line: str) -> None:
    with pytest.raises(AuthKeyError) as caught:
        parse_line(line)
    assert caught.value.reason == (
        "unsupported key type (it looks like an option; a blank ends the options)"
    )


def test_the_line_type_of_a_mismatch_is_cut_to_40_characters() -> None:
    with pytest.raises(AuthKeyError) as caught:
        parse_line(f"{SK_CERT} {BLOB}")
    assert caught.value.reason == (
        "line says 'sk-ecdsa-sha2-nistp256-cert-v01@openssh.'... (43 characters) "
        "but the key blob holds 'ssh-ed25519'"
    )


def test_the_blob_type_of_a_mismatch_is_cut_to_40_characters() -> None:
    sk_cert = b64(certificate(name=SK_CERT, key_fields=fields("ecdsa-sk")))
    assert parse_line(f"{SK_CERT} {sk_cert}").key_type == SK_CERT
    with pytest.raises(AuthKeyError) as caught:
        parse_line(f"ssh-ed25519 {sk_cert}")
    assert caught.value.reason == (
        "line says 'ssh-ed25519' but the key blob holds "
        "'sk-ecdsa-sha2-nistp256-cert-v01@openssh.'... (43 characters)"
    )


class Odd(str):
    """Text that never compares equal, so only a plain copy passes an equality check."""

    def __eq__(self, other: object) -> bool:
        return False

    __hash__ = str.__hash__


def test_option_values_come_back_as_plain_str() -> None:
    key = AuthorizedKey("ssh-ed25519", BLOB, (KeyOption("command", Odd("uptime")),))
    assert [type(value) for value in key.values("command")] == [str]
    assert type(build_line(key)) is str and 'command="uptime"' in build_line(key)


def test_public_key_checks_a_plain_copy_of_the_key_type() -> None:
    key = AuthorizedKey(Odd("ssh-ed25519"), BLOB)
    assert key.public_key().key_type == "ssh-ed25519"
    assert key.fingerprint() == parse_line(f"ssh-ed25519 {BLOB}").fingerprint()


def test_methods_of_public_classes_name_the_public_module() -> None:
    methods = [
        member
        for name in authkeyline.__all__
        if isinstance(getattr(authkeyline, name), type)
        for member in vars(getattr(authkeyline, name)).values()
        if callable(member) and hasattr(member, "__code__")
    ]
    assert methods and {method.__module__ for method in methods} == {"authkeyline"}
    data = pickle.dumps(AuthorizedKey.has_flag)
    assert b"authkeyline._" not in data and pickle.loads(data) is AuthorizedKey.has_flag
