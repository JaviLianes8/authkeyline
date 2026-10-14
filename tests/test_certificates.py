"""Certificate blobs: the body of draft-miller-ssh-cert-06 section 2, as cert_parse reads it."""

from __future__ import annotations

import struct

import pytest
from keyfactory import b64, blob, certificate, fields, string

from authkeyline import AuthKeyError, parse_line
from authkeyline._blob import decode_key

NAME = "ssh-ed25519-cert-v01@openssh.com"


def test_certificate_fields_are_exposed() -> None:
    data = certificate(principals=("alice", "bob"), extensions=(("permit-pty", b""),))
    key = parse_line(f"{NAME} {b64(data)} note").public_key()
    cert = key.certificate
    assert cert is not None
    assert (cert.cert_type, cert.serial, cert.key_id) == ("user", 7, "key-id")
    assert cert.principals == ("alice", "bob")
    assert (cert.valid_after, cert.valid_before) == (0, 2**64 - 1)
    assert cert.extensions == (("permit-pty", b""),) and cert.critical_options == ()
    assert cert.ca_key.key_type == "ssh-ed25519" and cert.signature_type == "ssh-ed25519"
    assert key.short_type == "ED25519-CERT" and key.bits == 256


def test_certificate_fingerprint_is_the_fingerprint_of_its_key() -> None:
    key_fields = fields("ed25519")
    cert = decode_key(certificate(key_fields=key_fields))
    plain = decode_key(string("ssh-ed25519") + key_fields)
    assert cert.fingerprint() == plain.fingerprint()
    assert cert.plain_blob == plain.blob


def test_host_certificate() -> None:
    cert = decode_key(certificate(cert_type=2)).certificate
    assert cert is not None and cert.cert_type == "host"


def test_unknown_certificate_type() -> None:
    with pytest.raises(AuthKeyError, match="neither user"):
        decode_key(certificate(cert_type=3))


def test_ca_must_be_a_plain_key() -> None:
    with pytest.raises(AuthKeyError, match="cannot sign a certificate"):
        decode_key(certificate(ca=certificate()))
    with pytest.raises(AuthKeyError, match="must be 32 bytes"):
        decode_key(certificate(ca=string("ssh-ed25519") + string(b"short")))


def test_principal_limit() -> None:
    assert decode_key(certificate(principals=tuple(f"p{i}" for i in range(256))))
    with pytest.raises(AuthKeyError, match="more than 256 principals"):
        decode_key(certificate(principals=tuple(f"p{i}" for i in range(257))))


def test_principal_with_a_nul_is_refused() -> None:
    with pytest.raises(AuthKeyError, match="NUL"):
        decode_key(certificate(principals=("a\0b",)))


def test_malformed_extension_section() -> None:
    broken = certificate(raw_extensions=string("permit-pty") + b"\0\0\0\x05ab")
    with pytest.raises(AuthKeyError, match="certificate extensions is truncated"):
        decode_key(broken)


def test_trailing_bytes_after_the_signature() -> None:
    with pytest.raises(AuthKeyError, match="trailing bytes"):
        decode_key(certificate() + b"x")


def test_rsa_and_ecdsa_certificates() -> None:
    rsa = decode_key(certificate("ssh-rsa-cert-v01@openssh.com", fields("rsa", bits=1024)))
    assert (rsa.bits, rsa.short_type) == (1024, "RSA-CERT")
    name = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
    ec = decode_key(certificate(name, fields("ecdsa", curve="nistp384")))
    assert (ec.bits, ec.short_type) == (384, "ECDSA-CERT")
    assert ec.plain_blob.startswith(string("ecdsa-sha2-nistp384"))


def test_certificate_line_type_must_match_its_blob() -> None:
    data = b64(certificate())
    with pytest.raises(AuthKeyError, match="holds"):
        parse_line(f"ssh-ed25519 {data}")
    plain = b64(blob("ssh-ed25519", "ed25519"))
    with pytest.raises(AuthKeyError, match="holds"):
        parse_line(f"{NAME} {plain}")


def test_serial_is_read_as_unsigned_64_bit() -> None:
    data = certificate()
    head = string(NAME)
    nonce_end = len(head) + 4 + 32 + len(fields("ed25519"))
    patched = data[:nonce_end] + struct.pack(">Q", 2**64 - 1) + data[nonce_end + 8 :]
    cert = decode_key(patched).certificate
    assert cert is not None and cert.serial == 2**64 - 1
