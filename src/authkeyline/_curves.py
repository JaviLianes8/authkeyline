"""Point checks for the NIST curves of ECDSA keys.

The primes and curve coefficients are those of RFC 5903 section 3,
https://www.rfc-editor.org/rfc/rfc5903.txt (tests/test_sources.py compares them with it).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Curve:
    bits: int
    p: int
    b: int

    @property
    def size(self) -> int:
        return (self.bits + 7) // 8


CURVES: dict[str, Curve] = {
    "nistp256": Curve(
        256,
        2**256 - 2**224 + 2**192 + 2**96 - 1,
        int("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16),
    ),
    "nistp384": Curve(
        384,
        2**384 - 2**128 - 2**96 + 2**32 - 1,
        int(
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
            "C656398D8A2ED19D2A85C8EDD3EC2AEF",
            16,
        ),
    ),
    "nistp521": Curve(
        521,
        2**521 - 1,
        int(
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1"
            "09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B50"
            "3F00",
            16,
        ),
    ),
}


def check_point(curve_name: str, point: bytes) -> None:
    """Raise ValueError unless ``point`` is an uncompressed point on the curve.

    The curves have cofactor 1, so a point on the curve that is not at infinity is in the
    prime order group: this is what sshkey_ec_validate_public needs as well.
    """
    curve = CURVES[curve_name]
    if len(point) != 1 + 2 * curve.size or point[0] != 0x04:
        raise ValueError(f"is not an uncompressed {curve_name} point")
    x = int.from_bytes(point[1 : 1 + curve.size], "big")
    y = int.from_bytes(point[1 + curve.size :], "big")
    p = curve.p
    if x >= p or y >= p or (y * y - (x * x * x - 3 * x + curve.b)) % p:
        raise ValueError(f"is not on the {curve_name} curve")
