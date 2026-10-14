from __future__ import annotations

import pytest
from keyfactory import b64, blob, ed25519_line, fields, string

from authkeyline import KEY_TYPES, AuthKeyError, KeyOption, parse_line

ED = ed25519_line("alice@host")
KEY = ED.split(" ", 1)[1]  # "<blob> alice@host"


def test_line_without_options() -> None:
    key = parse_line(ED)
    assert (key.key_type, key.options, key.comment) == ("ssh-ed25519", (), "alice@host")
    assert key.key_base64 == KEY.split()[0]


def test_flags_and_quoted_values_keep_commas_and_spaces() -> None:
    line = f'command="/bin/echo hi, there",from="10.0.0.1,10.0.0.2",no-pty ssh-ed25519 {KEY}'
    assert parse_line(line).options == (
        KeyOption("command", "/bin/echo hi, there"),
        KeyOption("from", "10.0.0.1,10.0.0.2"),
        KeyOption("no-pty"),
    )


def test_only_backslash_quote_is_an_escape() -> None:
    (option,) = parse_line(r'command="say \"hi\" c:\\x \n" ssh-ed25519 ' + KEY).options
    assert option.value == r'say "hi" c:\\x \n'


def test_option_names_keep_their_case_and_match_without_it() -> None:
    key = parse_line(f'NO-PTY,Command="x",X11-Forwarding ssh-ed25519 {KEY}')
    assert key.options[0] == KeyOption("NO-PTY")
    assert key.has_flag("no-pty") and key.has_flag("x11-forwarding")
    assert key.values("COMMAND") == ("x",) and key.values("from") == ()
    assert not key.has_flag("command")


def test_values_collects_every_repeat() -> None:
    line = f'permitopen="a:1",permitopen="b:2",environment="A=1" ssh-ed25519 {KEY}'
    assert parse_line(line).values("permitopen") == ("a:1", "b:2")


def test_tabs_separate_fields_and_comment_keeps_inner_spaces() -> None:
    key = parse_line(f"\t no-pty\tssh-ed25519 \t{KEY.split()[0]}  a  long comment \t\r\n")
    assert key.options == (KeyOption("no-pty"),)
    assert key.comment == "a  long comment"


def test_empty_elements_and_comma_before_the_key_are_skipped_like_sshd() -> None:
    assert parse_line(f",no-pty,,pty, ssh-ed25519 {KEY}").options == (
        KeyOption("no-pty"),
        KeyOption("pty"),
    )


@pytest.mark.parametrize("name", sorted(KEY_TYPES))
def test_every_key_type_parses(name: str) -> None:
    from authkeyline._keytypes import KEY_TYPES as TABLE

    kind = TABLE[name]
    curve = kind.curve or "nistp256"
    if kind.cert:
        from keyfactory import certificate

        data = certificate(name, fields(kind.family, curve=curve))
    else:
        data = blob(name, kind.family, curve=curve)
    key = parse_line(f"{name} {b64(data)}")
    assert key.public_key().key_type == name
    assert (key.public_key().certificate is not None) == kind.cert


def test_a_line_that_starts_with_a_key_type_has_no_options() -> None:
    assert parse_line(ED).options == ()


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("", "not an authorized_keys entry"),
        ("   # comment", "not an authorized_keys entry"),
        ("ssh-ed25519", "missing key blob"),
        ("no-pty", "missing key type"),
        ("no-pty ", "missing key type"),
        ("no-pty ssh-foo AAAA", "unsupported key type"),
        ("ssh-dss AAAA", "unknown option"),
        ("ssh-ed25519 AAAA\0 x", r"'\x00'"),
        ("ssh-ed25519 AAAA x\ry", r"'\r'"),
        ("ssh-ed25519 not+base64!!", "not valid base64"),
        ("ssh-ed25519 AAAAA", "not valid base64"),
    ],
)
def test_malformed_lines_raise(line: str, message: str) -> None:
    with pytest.raises(AuthKeyError) as caught:
        parse_line(line)
    assert message in str(caught.value)


def test_line_and_blob_types_must_agree() -> None:
    data = b64(blob("ssh-ed25519", "ed25519"))
    with pytest.raises(AuthKeyError, match="holds 'ssh-ed25519'"):
        parse_line(f"ssh-rsa {data}")


def test_rsa_signature_names_read_as_rsa_keys_like_sshd() -> None:
    data = b64(blob("ssh-rsa", "rsa"))
    assert parse_line(f"rsa-sha2-512 {data}").public_key().short_type == "RSA"
    other = b64(blob("rsa-sha2-256", "rsa"))
    assert parse_line(f"ssh-rsa {other}").public_key().key_type == "rsa-sha2-256"


def test_ecdsa_curve_must_agree_with_the_line() -> None:
    data = b64(blob("ecdsa-sha2-nistp384", "ecdsa", curve="nistp384"))
    with pytest.raises(AuthKeyError, match="holds"):
        parse_line(f"ecdsa-sha2-nistp256 {data}")


def test_key_bytes_is_the_decoded_blob() -> None:
    data = string("ssh-ed25519") + string(bytes(32))
    assert parse_line(f"ssh-ed25519 {b64(data)}").key_bytes() == data
