"""Reader for the SSH wire types of RFC 4251 section 5, with the limits OpenSSH applies."""

from __future__ import annotations

from ._errors import AuthKeyError

# sshbuf.h: SSHBUF_MAX_BIGNUM, 16384 bits; one extra zero byte may keep the top bit clear.
MAX_BIGNUM_BYTES = 16384 // 8
# sshbuf.h: SSHBUF_SIZE_MAX, the largest buffer OpenSSH decodes a key blob into.
MAX_BLOB_BYTES = 0x8000000


class Reader:
    """Consume a byte string field by field; any shortfall raises AuthKeyError."""

    def __init__(self, data: bytes, what: str = "key blob") -> None:
        self._data = data
        self._pos = 0
        self._what = what

    def _take(self, size: int) -> bytes:
        end = self._pos + size
        if end > len(self._data):
            raise AuthKeyError(f"{self._what} is truncated")
        chunk = self._data[self._pos : end]
        self._pos = end
        return chunk

    def u32(self) -> int:
        return int.from_bytes(self._take(4), "big")

    def u64(self) -> int:
        return int.from_bytes(self._take(8), "big")

    def string(self) -> bytes:
        return self._take(self.u32())

    def cstring_bytes(self) -> bytes:
        """A text field as sshbuf_get_cstring reads it: one NUL may end it, none may come before.

        OpenSSH then uses it as a C string, so that final NUL is not part of the text.
        """
        raw = self.string()
        if b"\0" in raw[:-1]:
            raise AuthKeyError(f"{self._what} has a NUL inside a text field")
        return raw.removesuffix(b"\0")

    def cstring(self) -> str:
        return self.cstring_bytes().decode("utf-8", errors="replace")

    def mpint(self) -> int:
        raw = self.string()
        if raw and raw[0] & 0x80:
            raise AuthKeyError(f"{self._what} has a negative integer")
        if len(raw) > MAX_BIGNUM_BYTES + 1 or (len(raw) == MAX_BIGNUM_BYTES + 1 and raw[0]):
            raise AuthKeyError(f"{self._what} has an integer larger than 16384 bits")
        return int.from_bytes(raw, "big")

    def at_end(self) -> bool:
        return self._pos == len(self._data)

    def finish(self) -> None:
        if not self.at_end():
            raise AuthKeyError(f"{self._what} has trailing bytes")


def put_string(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def put_mpint(value: int) -> bytes:
    """Minimal two's complement encoding of a non-negative integer, as sshbuf writes it."""
    if value == 0:
        return put_string(b"")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\0" + raw
    return put_string(raw)
