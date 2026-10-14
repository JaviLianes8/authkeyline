"""Key blobs are checked field by field, as sshkey_fromb does."""

from __future__ import annotations

import pytest
from keyfactory import b64, blob, ec_point, fields, mpint, string

from authkeyline import AuthKeyError, parse_line
from authkeyline._blob import decode_key


def line(data: bytes, key_type: str = "ssh-ed25519") -> str:
    return f"{key_type} {b64(data)}"


def rejects(data: bytes, message: str, key_type: str = "ssh-ed25519") -> None:
    with pytest.raises(AuthKeyError) as caught:
        parse_line(line(data, key_type))
    assert message in str(caught.value), caught.value


def test_unknown_type_inside_the_blob() -> None:
    rejects(string("ssh-dss") + fields("ed25519"), "unsupported key type 'ssh-dss'")


def test_truncated_and_trailing_bytes() -> None:
    good = blob("ssh-ed25519", "ed25519")
    rejects(good[:-1], "truncated")
    rejects(good + b"\0", "trailing bytes")
    rejects(b"\0\0\0", "truncated")


def test_ed25519_key_must_be_32_bytes() -> None:
    rejects(string("ssh-ed25519") + string(bytes(31)), "must be 32 bytes")
    rejects(string("ssh-ed25519") + string(bytes(33)), "must be 32 bytes")


def test_mldsa_key_size() -> None:
    name = "ssh-mldsa44-ed25519"
    assert parse_line(line(blob(name, "mldsa44-ed25519"), name)).public_key().bits == 512
    rejects(string(name) + string(bytes(1343)), "must be 1344 bytes", name)


def test_type_name_with_a_nul_is_refused() -> None:
    rejects(string("ssh-ed25519\0x") + fields("ed25519"), "NUL")


@pytest.mark.parametrize("curve", ["nistp256", "nistp384", "nistp521"])
def test_ecdsa_points_are_checked(curve: str) -> None:
    name = f"ecdsa-sha2-{curve}"
    point = ec_point(curve)
    key = parse_line(line(string(name) + string(curve) + string(point), name)).public_key()
    assert key.bits == {"nistp256": 256, "nistp384": 384, "nistp521": 521}[curve]
    off_curve = point[:-1] + bytes([point[-1] ^ 1])
    rejects(string(name) + string(curve) + string(off_curve), "not on the", name)
    compressed = bytes([2 + (point[-1] & 1)]) + point[1 : 1 + (len(point) - 1) // 2]
    rejects(string(name) + string(curve) + string(compressed), "uncompressed", name)
    rejects(string(name) + string(curve) + string(b"\x04" + point[1:-1]), "uncompressed", name)


def test_ecdsa_coordinates_must_be_below_the_prime() -> None:
    from authkeyline._curves import CURVES

    curve = CURVES["nistp256"]
    point = ec_point("nistp256")
    x = int.from_bytes(point[1:33], "big") + curve.p
    if x < 2**256:
        shifted = b"\x04" + x.to_bytes(32, "big") + point[33:]
        rejects(string("ecdsa-sha2-nistp256") + string("nistp256") + string(shifted), "not on")


def test_ecdsa_curve_name_must_match_the_type() -> None:
    name = "ecdsa-sha2-nistp256"
    bad = string(name) + string("nistp384") + string(ec_point("nistp384"))
    rejects(bad, "names curve 'nistp384'", name)


def test_security_keys_carry_an_application() -> None:
    name = "sk-ssh-ed25519@openssh.com"
    key = parse_line(line(blob(name, "ed25519-sk"), name)).public_key()
    assert key.application == "ssh:" and key.short_type == "ED25519-SK"
    rejects(string(name) + string(bytes(32)), "truncated", name)
    sk_ecdsa = "sk-ecdsa-sha2-nistp256@openssh.com"
    key = parse_line(line(blob(sk_ecdsa, "ecdsa-sk"), sk_ecdsa)).public_key()
    assert (key.application, key.bits, key.short_type) == ("ssh:", 256, "ECDSA-SK")


def test_rsa_size_floor_and_integer_rules() -> None:
    name = "ssh-rsa"
    assert parse_line(line(blob(name, "rsa", bits=1024), name)).public_key().bits == 1024
    rejects(blob(name, "rsa", bits=1023), "below the 1024 bit floor", name)
    modulus = 1 << 2047 | 1
    negative = string(name) + mpint(65537) + string(b"\x80" + bytes(255))
    rejects(negative, "negative", name)
    too_big = string(name) + mpint(3) + string(b"\x01" + bytes(2048))
    rejects(too_big, "larger than 16384 bits", name)
    padded = string(name) + mpint(65537) + mpint(modulus, pad=2)
    assert parse_line(line(padded, name)).public_key().bits == 2048


def test_largest_rsa_modulus_is_accepted() -> None:
    modulus = (1 << 16384) - 1
    data = string("ssh-rsa") + mpint(65537) + mpint(modulus)
    assert parse_line(line(data, "ssh-rsa")).public_key().bits == 16384


def test_fingerprint_uses_the_canonical_plain_blob() -> None:
    modulus = 1 << 2047 | 12345
    canonical = string("ssh-rsa") + mpint(65537) + mpint(modulus)
    padded = string("rsa-sha2-256") + mpint(65537, pad=3) + mpint(modulus, pad=1)
    assert decode_key(padded).plain_blob == canonical
    assert decode_key(padded).fingerprint() == decode_key(canonical).fingerprint()


def test_fingerprint_formats() -> None:
    key = decode_key(string("ssh-ed25519") + string(bytes(32)))
    sha = key.fingerprint()
    assert sha.startswith("SHA256:") and len(sha) == 7 + 43 and not sha.endswith("=")
    md5 = key.fingerprint("md5")
    assert md5.startswith("MD5:") and len(md5.split(":")) == 17
    with pytest.raises(AuthKeyError, match="unknown fingerprint hash"):
        key.fingerprint("sha1")  # type: ignore[arg-type]
    assert parse_line(line(key.blob)).fingerprint("md5") == md5
