"""Fresh throwaway public keys and certificates for the tests, built from random numbers.

They are structurally valid (what sshd checks when it reads a line) but no private key is
kept. ECDSA points are k * G with the generators of RFC 5903 section 3,
https://www.rfc-editor.org/rfc/rfc5903.txt (tests/test_sources.py compares them).
"""

from __future__ import annotations

import base64
import secrets
import struct

from authkeyline._curves import CURVES

GENERATORS = {
    "nistp256": (
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
    ),
    "nistp384": (
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38"
        "5502F25DBF55296C3A545E3872760AB7",
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0"
        "0A60B1CE1D7E819D7A431D7C90EA0E5F",
    ),
    "nistp521": (
        "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D"
        "3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
        "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E"
        "662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
    ),
}

Point = tuple[int, int] | None


def string(data: bytes | str) -> bytes:
    raw = data.encode() if isinstance(data, str) else data
    return struct.pack(">I", len(raw)) + raw


def mpint(value: int, pad: int = 0) -> bytes:
    raw = value.to_bytes((value.bit_length() + 8) // 8, "big") if value else b""
    return string(b"\0" * pad + raw)


def b64(blob: bytes) -> str:
    return base64.b64encode(blob).decode()


def _add(a: Point, b: Point, p: int) -> Point:
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % p == 0:
        return None
    if a == b:
        slope = (3 * a[0] * a[0] - 3) * pow(2 * a[1], -1, p) % p
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], -1, p) % p
    x = (slope * slope - a[0] - b[0]) % p
    return x, (slope * (a[0] - x) - a[1]) % p


def ec_point(curve: str) -> bytes:
    """An uncompressed random point on ``curve``."""
    p, size = CURVES[curve].p, CURVES[curve].size
    gx, gy = GENERATORS[curve]
    base: Point = (int(gx, 16), int(gy, 16))
    result: Point = None
    k = secrets.randbits(CURVES[curve].bits - 8) | 1
    while k:
        if k & 1:
            result = _add(result, base, p)
        base = _add(base, base, p)
        k >>= 1
    assert result is not None
    return b"\x04" + result[0].to_bytes(size, "big") + result[1].to_bytes(size, "big")


def fields(kind: str, curve: str = "nistp256", bits: int = 2048) -> bytes:
    """The key fields after the type name for a family of sshkey.c."""
    if kind == "rsa":
        return mpint(65537) + mpint(secrets.randbits(bits) | (1 << (bits - 1)) | 1)
    if kind == "ed25519":
        return string(secrets.token_bytes(32))
    if kind == "ed25519-sk":
        return string(secrets.token_bytes(32)) + string("ssh:")
    if kind == "mldsa44-ed25519":
        return string(secrets.token_bytes(1344))
    point = string(curve) + string(ec_point(curve))
    return point + string("ssh:") if kind == "ecdsa-sk" else point


def blob(name: str, kind: str, **kw: object) -> bytes:
    return string(name) + fields(kind, **kw)  # type: ignore[arg-type]


def ed25519_line(comment: str = "throwaway") -> str:
    return f"ssh-ed25519 {b64(blob('ssh-ed25519', 'ed25519'))} {comment}".rstrip()


def certificate(
    name: str = "ssh-ed25519-cert-v01@openssh.com",
    key_fields: bytes | None = None,
    cert_type: int = 1,
    principals: tuple[str, ...] = ("alice",),
    ca: bytes | None = None,
    extensions: tuple[tuple[str, bytes], ...] = (("permit-pty", b""),),
    raw_extensions: bytes | None = None,
    signature: str = "ssh-ed25519",
) -> bytes:
    """A certificate blob with a random nonce and a placeholder signature."""
    body = string(name) + string(secrets.token_bytes(32))
    body += key_fields if key_fields is not None else fields("ed25519")
    body += struct.pack(">QI", 7, cert_type) + string("key-id")
    body += string(b"".join(string(p) for p in principals))
    body += struct.pack(">QQ", 0, 2**64 - 1) + string(b"")
    packed = b"".join(string(n) + string(d) for n, d in extensions)
    body += string(packed if raw_extensions is None else raw_extensions) + string(b"")
    body += string(ca if ca is not None else blob("ssh-ed25519", "ed25519"))
    return body + string(string(signature) + string(secrets.token_bytes(64)))
