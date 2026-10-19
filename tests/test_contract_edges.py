"""Edges the author mutation round showed were not pinned: coordinate ranges and comment starts."""

from __future__ import annotations

import pytest
from keyfactory import b64, ec_point, ed25519_line, string

from authkeyline import AuthKeyError, parse_line
from authkeyline._curves import CURVES


def _ecdsa_line(curve: str, point: bytes) -> str:
    name = f"ecdsa-sha2-{curve}"
    return f"{name} {b64(string(name) + string(curve) + string(point))}"


def _unreduced(curve: str) -> bytes:
    """(p, sqrt(b)): on the curve modulo p, but x is not below p, which OpenSSL refuses."""
    spec = CURVES[curve]
    y = pow(spec.b, (spec.p + 1) // 4, spec.p)
    assert y * y % spec.p == spec.b  # b is a square for the three curves
    return b"\x04" + spec.p.to_bytes(spec.size, "big") + y.to_bytes(spec.size, "big")


@pytest.mark.parametrize("curve", sorted(CURVES))
def test_coordinates_must_be_below_the_prime(curve: str) -> None:
    with pytest.raises(AuthKeyError, match="is not on the"):
        parse_line(_ecdsa_line(curve, _unreduced(curve)))
    spec = CURVES[curve]
    point = ec_point(curve)
    x, y = point[1 : 1 + spec.size], int.from_bytes(point[1 + spec.size :], "big")
    lifted = b"\x04" + x + (y + spec.p).to_bytes(spec.size + 1, "big")[1:]
    if y + spec.p < 256**spec.size:
        with pytest.raises(AuthKeyError, match="is not on the"):
            parse_line(_ecdsa_line(curve, lifted))
    assert parse_line(_ecdsa_line(curve, point)).public_key().bits == spec.bits


@pytest.mark.parametrize("start", ["\v", "\f", "\r", chr(0x3000), "\x1c", chr(0xA0)])
def test_the_comment_starts_after_spaces_and_tabs_only(start: str) -> None:
    line = ed25519_line("") + " \t " + start + "note"
    assert parse_line(line).comment == start + "note"


@pytest.mark.parametrize("end", ["\v", "\f", chr(0x3000)])
def test_only_spaces_tabs_and_cr_are_trimmed_from_the_comment_end(end: str) -> None:
    line = ed25519_line("") + " note" + end + " \r"
    assert parse_line(line).comment == "note" + end
