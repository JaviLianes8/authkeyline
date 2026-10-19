"""Contracts the QA mutation round found missing: limits, wire text, certificates, integers."""

from __future__ import annotations

import base64
import hashlib
import struct

import pytest
from keyfactory import b64, blob, certificate, ec_point, mpint, string

import authkeyline._blob
from authkeyline import AuthKeyError, LineProblem, check_file, parse_file, parse_line
from authkeyline._optrules import ENV_MAX, NI_MAXHOST
from authkeyline._wire import put_mpint

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"


def test_environment_limit_counts_names_not_values() -> None:
    same_name = ",".join(f'environment="A={i}"' for i in range(ENV_MAX + 100))
    key = parse_line(f"{same_name} {KEY}")
    assert len(key.options) == ENV_MAX + 100 and key.environment() == {"A": "0"}


@pytest.mark.parametrize("char", ["\xe9", "\udce9"], ids=["two-byte", "escaped-byte"])
def test_permit_host_length_is_counted_in_bytes(char: str) -> None:
    width = len(char.encode("utf-8", "surrogateescape"))
    longest = char * ((NI_MAXHOST - 1) // width)
    parse_line(f'permitopen="{longest}:22" {KEY}')
    too_long = char * -(-NI_MAXHOST // width)
    with pytest.raises(AuthKeyError, match="host name is too long"):
        parse_line(f'permitopen="{too_long}:22" {KEY}')


@pytest.mark.parametrize("prefix", [b"\x02", b"\x03"])
def test_compressed_prefix_at_the_uncompressed_length_is_refused(prefix: bytes) -> None:
    point = prefix + ec_point("nistp256")[1:]
    data = string("ecdsa-sha2-nistp256") + string("nistp256") + string(point)
    with pytest.raises(AuthKeyError, match="not an uncompressed nistp256 point"):
        parse_line(f"ecdsa-sha2-nistp256 {b64(data)}")


@pytest.mark.parametrize("space", ["\xa0", "\u2003", "\u3000"], ids=["nbsp", "em", "ideographic"])
def test_a_line_of_unicode_whitespace_is_not_blank(space: str) -> None:
    reason = f"unknown option {space!r}"
    assert check_file(f"{space}\n") == [LineProblem(1, reason)]
    with pytest.raises(AuthKeyError, match="line 1: unknown option"):
        parse_file(f"{space}\n")
    with pytest.raises(AuthKeyError) as caught:
        parse_line(space)
    assert caught.value.reason == reason


def test_one_trailing_nul_ends_wire_text_fields() -> None:
    plain = blob("ssh-ed25519", "ed25519")
    with_nul = string(b"ssh-ed25519\0") + plain[len(string("ssh-ed25519")) :]
    assert parse_line(f"ssh-ed25519 {b64(with_nul)}").public_key().key_type == "ssh-ed25519"
    data = certificate(principals=("alice\0", "bob")).replace(string("key-id"), string(b"key-id\0"))
    cert = parse_line(f"ssh-ed25519-cert-v01@openssh.com {b64(data)}").public_key().certificate
    assert cert is not None
    assert (cert.key_id, cert.principals) == ("key-id", ("alice", "bob"))


def test_certificate_option_and_extension_data_is_kept() -> None:
    validity = struct.pack(">QQ", 0, 2**64 - 1)
    critical = string(string("force-command") + string(string("uptime")))
    data = certificate(extensions=(("permit-pty", b""), ("x-data", b"\x00\x01d"))).replace(
        validity + string(b""), validity + critical
    )
    cert = parse_line(f"ssh-ed25519-cert-v01@openssh.com {b64(data)}").public_key().certificate
    assert cert is not None
    assert cert.critical_options == (("force-command", b"\x00\x00\x00\x06uptime"),)
    assert cert.extensions == (("permit-pty", b""), ("x-data", b"\x00\x01d"))


def test_webauthn_signature_from_a_security_key_ca() -> None:
    ca = blob("sk-ecdsa-sha2-nistp256@openssh.com", "ecdsa-sk")
    name = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
    data = certificate(ca=ca, signature=name)
    cert = parse_line(f"ssh-ed25519-cert-v01@openssh.com {b64(data)}").public_key().certificate
    assert cert is not None and cert.signature_type == name


def test_a_zero_rsa_exponent_is_fingerprinted_as_an_empty_integer() -> None:
    assert put_mpint(0) == b"\0\0\0\0"
    modulus = (1 << 2047) | int.from_bytes(bytes(range(1, 200)), "big")
    data = string("ssh-rsa") + mpint(0) + mpint(modulus)
    digest = base64.b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
    assert parse_line(f"ssh-rsa {b64(data)}").fingerprint() == "SHA256:" + digest


def test_the_decoded_size_cap_holds_at_its_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(authkeyline._blob, "MAX_BLOB_BYTES", 100)
    over = b64(bytes(101))
    assert len(over) == (100 // 3 + 1) * 4  # passes the cap on the text
    with pytest.raises(AuthKeyError, match="larger than OpenSSH's 100 byte buffer"):
        parse_line(f"ssh-ed25519 {over}")
    with pytest.raises(AuthKeyError) as caught:
        parse_line(f"ssh-ed25519 {b64(bytes(100))}")
    assert "larger" not in str(caught.value)
