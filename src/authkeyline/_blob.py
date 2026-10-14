"""Decode and check a public key blob the way sshkey_fromb does."""

from __future__ import annotations

import base64
import binascii

from ._cert import read_certificate
from ._curves import CURVES, check_point
from ._errors import AuthKeyError
from ._keytypes import KEY_TYPES, PLAIN_NAMES, KeyType, short_name
from ._records import PublicKey
from ._wire import Reader, put_mpint, put_string

# sshkey.h SSH_RSA_MINIMUM_MODULUS_SIZE; crypto_api.h sizes of the raw public keys.
RSA_MIN_BITS = 1024
ED25519_SIZE = 32
MLDSA44_ED25519_SIZE = 1312 + 32
# sshkey_size falls back to the impl keybits for key types without a size function.
_FIXED_BITS = {"ed25519": 256, "ed25519-sk": 256, "mldsa44-ed25519": 512}


def decode_base64(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AuthKeyError(f"key blob is not valid base64: {text[:40]!r}") from exc


def decode_key(blob: bytes, *, allow_cert: bool = True) -> PublicKey:
    """Decode a public key blob, checking every field; raise AuthKeyError if any is wrong."""
    reader = Reader(blob)
    name = reader.cstring()
    kind = KEY_TYPES.get(name)
    if kind is None:
        raise AuthKeyError(f"key blob holds an unsupported key type {name!r}")
    if kind.cert and not allow_cert:
        raise AuthKeyError("a certificate cannot sign a certificate")
    if kind.cert:
        reader.string()  # nonce
    plain, bits, application = _read_fields(reader, kind)
    certificate = None
    if kind.cert:
        certificate = read_certificate(reader, lambda ca: decode_key(ca, allow_cert=False))
    reader.finish()
    return PublicKey(
        key_type=name,
        short_type=short_name(kind),
        bits=bits,
        blob=blob,
        plain_blob=plain,
        application=application,
        certificate=certificate,
    )


def _read_fields(reader: Reader, kind: KeyType) -> tuple[bytes, int, str | None]:
    """Read the key fields; return the plain blob ssh-keygen would write, bits, application."""
    head = put_string(PLAIN_NAMES[(kind.family, kind.curve)].encode())
    if kind.family == "rsa":
        exponent, modulus = reader.mpint(), reader.mpint()
        bits = modulus.bit_length()
        if bits < RSA_MIN_BITS:
            raise AuthKeyError(f"RSA modulus of {bits} bits is below the {RSA_MIN_BITS} bit floor")
        return head + put_mpint(exponent) + put_mpint(modulus), bits, None
    if kind.family in ("ed25519", "ed25519-sk", "mldsa44-ed25519"):
        public = reader.string()
        size = ED25519_SIZE if kind.family != "mldsa44-ed25519" else MLDSA44_ED25519_SIZE
        if len(public) != size:
            raise AuthKeyError(f"{kind.short} public key must be {size} bytes, not {len(public)}")
        fields, bits = put_string(public), _FIXED_BITS[kind.family]
    else:
        assert kind.curve is not None
        curve = reader.cstring()
        if curve != kind.curve:
            raise AuthKeyError(f"key blob names curve {curve!r}, its type needs {kind.curve!r}")
        point = reader.string()
        try:
            check_point(kind.curve, point)
        except ValueError as exc:
            raise AuthKeyError(f"ECDSA public key {exc}") from None
        fields, bits = put_string(curve.encode()) + put_string(point), CURVES[curve].bits
    if not kind.family.endswith("-sk"):
        return head + fields, bits, None
    application = reader.cstring_bytes()
    text = application.decode("utf-8", errors="replace")
    return head + fields + put_string(application), bits, text
