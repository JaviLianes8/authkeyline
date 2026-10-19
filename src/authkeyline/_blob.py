"""Decode and check a public key blob the way sshkey_fromb does."""

from __future__ import annotations

import base64
import binascii

from ._cert import read_certificate
from ._curves import CURVES, check_point
from ._errors import AuthKeyError, shown
from ._keytypes import KEY_TYPES, PLAIN_NAMES, KeyType, short_name
from ._records import PublicKey
from ._wire import MAX_BLOB_BYTES, Reader, put_mpint, put_string

# sshkey.h SSH_RSA_MINIMUM_MODULUS_SIZE; crypto_api.h sizes of the raw public keys.
RSA_MIN_BITS = 1024
ED25519_SIZE = 32
MLDSA44_ED25519_SIZE = 1312 + 32
# sshkey_size falls back to the impl keybits for key types without a size function.
_FIXED_BITS = {"ed25519": 256, "ed25519-sk": 256, "mldsa44-ed25519": 512}
# isspace() in the C locale; b64_pton skips these anywhere in the blob.
_C_SPACE = str.maketrans("", "", " \t\n\v\f\r")


def decode_base64(text: str) -> bytes:
    """Decode as OpenSSH's b64_pton: whitespace skipped, padding and zero spare bits required."""
    clean = text.translate(_C_SPACE)
    # Text this long cannot decode to MAX_BLOB_BYTES or less, so it is not decoded at all.
    if len(clean) > (MAX_BLOB_BYTES // 3 + 1) * 4:
        raise _too_big()
    try:
        if not _whole_quanta(clean):
            raise ValueError("padding too long or not at the end")
        raw = base64.b64decode(clean, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AuthKeyError(f"key blob is not valid base64{_shown_blob(text)}") from exc
    if base64.b64encode(raw).decode("ascii") != clean:
        raise AuthKeyError(f"key blob is not canonical base64{_shown_blob(text)}")
    if len(raw) > MAX_BLOB_BYTES:
        raise _too_big()
    return raw


def _whole_quanta(clean: str) -> bool:
    """Whole four character groups with at most two "=", all at the end.

    Checked before b64decode because Python 3.10 and 3.11 let excess padding through,
    which made the message depend on the Python.
    """
    data = clean.rstrip("=")
    return "=" not in data and len(clean) % 4 == 0 and len(clean) - len(data) <= 2


def _shown_blob(text: str) -> str:
    """The blob field for a message; one that looks like an option is described, not quoted."""
    # "ssh-ed25519 environment=..." puts an option where the blob goes, and its value may be
    # a secret. Base64 holds "=" only as trailing padding and never a quote.
    if '"' in text or "=" in text.translate(_C_SPACE).rstrip("="):
        return " (it looks like an option, so it is not quoted)"
    return f": {shown(text)}"


def _too_big() -> AuthKeyError:
    return AuthKeyError(f"key blob is larger than OpenSSH's {MAX_BLOB_BYTES} byte buffer")


def decode_key(blob: bytes, *, allow_cert: bool = True) -> PublicKey:
    """Decode a public key blob, checking every field; raise AuthKeyError if any is wrong."""
    reader = Reader(blob)
    name = reader.cstring()
    kind = KEY_TYPES.get(name)
    if kind is None:
        raise AuthKeyError(f"key blob holds an unsupported key type {shown(name)}")
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
            raise AuthKeyError(
                f"key blob names curve {shown(curve)}, its type needs {kind.curve!r}"
            )
        point = reader.string()
        try:
            check_point(kind.curve, point)
        except ValueError as exc:
            raise AuthKeyError(f"ECDSA public key {exc}") from None
        fields, bits = put_string(curve.encode()) + put_string(point), CURVES[curve].bits
    if not kind.family.endswith("-sk"):
        return head + fields, bits, None
    # The application is re-encoded without a final NUL, as ssh-keygen writes it back.
    application = reader.cstring_bytes()
    text = application.decode("utf-8", errors="replace")
    return head + fields + put_string(application), bits, text
