"""The certificate body that follows the key fields (draft-miller-ssh-cert-06 section 2)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from ._errors import AuthKeyError, shown
from ._keytypes import KEY_TYPES, SIGNATURE_NAMES
from ._records import Certificate, PublicKey
from ._wire import Reader

# sshkey.h SSHKEY_CERT_MAX_PRINCIPALS
MAX_PRINCIPALS = 256
_CERT_TYPES: dict[int, Literal["user", "host"]] = {1: "user", 2: "host"}


def read_certificate(reader: Reader, decode_ca: Callable[[bytes], PublicKey]) -> Certificate:
    """Read serial through signature; the CA key is decoded by ``decode_ca``."""
    serial = reader.u64()
    type_code = reader.u32()
    key_id = reader.cstring()
    principals = Reader(reader.string(), "certificate principals")
    valid_after, valid_before = reader.u64(), reader.u64()
    critical = _pairs(reader.string(), "certificate critical options")
    extensions = _pairs(reader.string(), "certificate extensions")
    reader.string()  # reserved
    ca_blob = reader.string()
    signature = Reader(reader.string(), "certificate signature")
    signature_type = signature.cstring()
    ca_key = decode_ca(ca_blob)
    ca_kind = KEY_TYPES[ca_key.key_type]
    if signature_type not in SIGNATURE_NAMES[(ca_kind.family, ca_kind.curve)]:
        raise AuthKeyError(
            f"certificate signature {shown(signature_type)} cannot come from a {ca_kind.short} CA"
        )
    cert_type = _CERT_TYPES.get(type_code)
    if cert_type is None:
        raise AuthKeyError(f"certificate type {type_code} is neither user (1) nor host (2)")
    names: list[str] = []
    while not principals.at_end():
        if len(names) >= MAX_PRINCIPALS:
            raise AuthKeyError(f"certificate lists more than {MAX_PRINCIPALS} principals")
        names.append(principals.cstring())
    return Certificate(
        cert_type=cert_type,
        serial=serial,
        key_id=key_id,
        principals=tuple(names),
        valid_after=valid_after,
        valid_before=valid_before,
        critical_options=critical,
        extensions=extensions,
        ca_key=ca_key,
        signature_type=signature_type,
    )


def _pairs(data: bytes, what: str) -> tuple[tuple[str, bytes], ...]:
    reader = Reader(data, what)
    pairs: list[tuple[str, bytes]] = []
    while not reader.at_end():
        name = reader.string().decode("utf-8", errors="replace")
        pairs.append((name, reader.string()))
    return tuple(pairs)
