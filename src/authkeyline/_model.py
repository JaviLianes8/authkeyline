"""Typed records for a single OpenSSH authorized_keys line."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ._blob import decode_base64, decode_key
from ._keycheck import check_type_agrees
from ._records import PublicKey


@dataclass(frozen=True)
class KeyOption:
    """One entry of the leading options field.

    A flag (``no-pty``) has ``value`` set to ``None``. A valued option (``command="..."``)
    keeps the text between the quotes in ``value``, with ``\\"`` turned into ``"``.
    ``name`` is kept as written; sshd compares option names case-insensitively.
    """

    name: str
    value: str | None = None


@dataclass(frozen=True)
class AuthorizedKey:
    """A parsed authorized_keys line: options, key type, base64 blob and comment."""

    key_type: str
    key_base64: str
    options: tuple[KeyOption, ...] = ()
    comment: str = ""

    def key_bytes(self) -> bytes:
        """Decode the base64 blob to raw bytes."""
        return decode_base64(self.key_base64)

    def public_key(self) -> PublicKey:
        """Decode and check the blob; its type must agree with ``key_type``."""
        key = decode_key(self.key_bytes())
        check_type_agrees(self.key_type, key.key_type)
        return key

    def fingerprint(self, hash: Literal["sha256", "md5"] = "sha256") -> str:
        """The key fingerprint as ``ssh-keygen -l -E <hash>`` prints it."""
        return self.public_key().fingerprint(hash)

    def values(self, name: str) -> tuple[str, ...]:
        """The values of every option called ``name``, compared case-insensitively."""
        wanted = name.lower()
        return tuple(
            option.value
            for option in self.options
            if option.value is not None and option.name.lower() == wanted
        )

    def environment(self) -> dict[str, str]:
        """The ``environment`` options as a mapping; the first value of a name wins, as in sshd."""
        variables: dict[str, str] = {}
        for value in self.values("environment"):
            name, _, text = value.partition("=")
            variables.setdefault(name, text)
        return variables

    def has_flag(self, name: str) -> bool:
        """Whether the flag ``name`` (``restrict``, ``no-pty``) is set, case-insensitively."""
        wanted = name.lower()
        return any(o.value is None and o.name.lower() == wanted for o in self.options)
