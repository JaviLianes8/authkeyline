"""Regression tests for the findings of the independent review."""

from __future__ import annotations

import base64
import io
import sys
from pathlib import Path

import pytest
from keyfactory import b64, blob, certificate, ed25519_line, fields

from authkeyline import AuthKeyError, check_file, parse_line
from authkeyline._blob import decode_key
from authkeyline._cli import main


def test_base64_with_spare_bits_set_is_refused() -> None:
    text = b64(blob("ecdsa-sha2-nistp256", "ecdsa"))  # 104 bytes: spare bits before one "="
    assert text.endswith("=") and not text.endswith("==")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    tampered = text[:-2] + alphabet[alphabet.index(text[-2]) ^ 1] + "="
    assert base64.b64decode(tampered) == base64.b64decode(text)
    with pytest.raises(AuthKeyError, match="not canonical base64"):
        parse_line(f"ecdsa-sha2-nistp256 {tampered}")
    assert parse_line(f"ecdsa-sha2-nistp256 {text}").key_base64 == text


def test_whitespace_inside_the_blob_is_skipped_like_b64_pton() -> None:
    text = b64(blob("ssh-ed25519", "ed25519"))
    key = parse_line(f"ssh-ed25519 {text[:8]}\v{text[8:]}\f c")
    assert key.key_bytes() == base64.b64decode(text)


@pytest.mark.parametrize("tail", ["foo\rbar", "foo\0bar", "c\r \r", "\0"])
def test_comment_characters_sshd_ignores_are_accepted(tail: str) -> None:
    line = ed25519_line("") + " " + tail
    key = parse_line(line)
    assert "\0" not in key.comment
    assert check_file(line) == []


def test_a_nul_ends_the_line_like_a_c_string() -> None:
    good = ed25519_line("x")
    assert parse_line(good + "\0no-pty garbage").comment == "x"
    with pytest.raises(AuthKeyError, match="missing key blob"):
        parse_line("ssh-ed25519\0" + good)


def test_certificate_signature_type_must_fit_the_ca() -> None:
    rsa_ca = blob("ssh-rsa", "rsa")
    with pytest.raises(AuthKeyError, match="cannot come from a RSA CA"):
        decode_key(certificate(ca=rsa_ca))  # signature named ssh-ed25519


def test_certificate_signatures_are_not_verified_unlike_sshd() -> None:
    """A documented gap: the body is checked, the signature bytes are not."""
    data = certificate(key_fields=fields("ed25519"))
    flipped = data[:-1] + bytes([data[-1] ^ 1])
    assert decode_key(flipped).certificate is not None


@pytest.mark.parametrize("value", ["+1", " 1", "-0", "\t7"])
def test_tunnel_numbers_read_as_strtonum_reads_them(value: str) -> None:
    assert parse_line(f'tunnel="{value}" {ed25519_line()}').options[0].value == value


@pytest.mark.parametrize("value", ["h:+22", "h: 22", "[::1]:\t80"])
def test_ports_read_as_strtonum_reads_them(value: str) -> None:
    parse_line(f'permitopen="{value}" {ed25519_line()}')
    parse_line(f'permitlisten=" 8080",permitlisten="+9" {ed25519_line()}')


@pytest.mark.parametrize("value", ["h:-22", "h:+0", "h:22 ", "h:2 2"])
def test_ports_still_refused(value: str) -> None:
    with pytest.raises(AuthKeyError, match="permitopen"):
        parse_line(f'permitopen="{value}" {ed25519_line()}')


@pytest.mark.parametrize("value", ["19700101Z", "197001010000UTC", "19700101000000z"])
def test_expiry_at_the_epoch_is_refused(value: str) -> None:
    with pytest.raises(AuthKeyError, match="the epoch"):
        parse_line(f'expiry-time="{value}" {ed25519_line()}')
    parse_line(f'expiry-time="19700101000001Z" {ed25519_line()}')


def test_cli_reports_unreadable_files_with_status_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    good = tmp_path / "keys"
    good.write_text(ed25519_line("ok") + "\n")
    code = main([str(tmp_path / "missing"), str(tmp_path), str(good)])
    out, err = capsys.readouterr()
    assert code == 2
    assert err.count("authkeyline: ") == 2 and str(tmp_path / "missing") in err
    assert out.rstrip().endswith("ok (ED25519)")


def test_cli_escapes_non_utf8_comment_bytes_like_ssh_keygen(
    tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    path = tmp_path / "keys"
    path.write_bytes(ed25519_line("caf").encode() + b"\xe9 \xff\n")
    assert main([str(path)]) == 0
    out = capsysbinary.readouterr().out
    assert out.endswith(rb" caf\351 \377 (ED25519)" + b"\n")


def test_cli_reads_stdin_as_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = ed25519_line("n").encode() + b"\xe9\n"
    out = io.BytesIO()

    class Stream(io.TextIOWrapper):
        pass

    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw), encoding="ascii"))
    monkeypatch.setattr(sys, "stdout", Stream(out, encoding="ascii"))
    assert main([]) == 0
    assert out.getvalue().endswith(rb" n\351 (ED25519)" + b"\n")


def test_rsa_ca_with_rsa_signature_names() -> None:
    for name in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"):
        data = certificate(ca=blob("ssh-rsa", "rsa"), signature=name)
        cert = decode_key(data).certificate
        assert cert is not None and cert.signature_type == name
