"""Typed records for a single OpenSSH authorized_keys line."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ._blob import decode_base64, decode_key
from ._errors import require_str
from ._keycheck import check_type_agrees
from ._records import PublicKey


@dataclass(frozen=True)
class KeyOption:
    """One entry of the leading options field.

    A flag (``no-pty``) has ``value`` set to ``None``. A valued option (``command="..."``)
    keeps the text between the quotes in ``value``, with ``\\"`` turned into ``"``.
    ``name`` is kept as written; sshd compares option names case-insensitively.

    >>> from authkeyline import KeyOption, parse_line
    >>> blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
    >>> parse_line(f'No-Pty,command="echo \\\\"hi\\\\"" ssh-ed25519 {blob}').options
    (KeyOption(name='No-Pty', value=None), KeyOption(name='command', value='echo "hi"'))
    """

    name: str
    value: str | None = None


@dataclass(frozen=True)
class AuthorizedKey:
    """A parsed authorized_keys line: options, key type, base64 blob and comment.

    ``key_type`` is the name written on the line and ``comment`` the rest of the line
    after the blob, without trailing spaces, tabs or CR. The record holds text only; the
    blob is decoded and checked by :meth:`public_key`. Records are frozen and compare by
    value; :func:`build_line` writes one back.

    >>> from authkeyline import parse_line
    >>> blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
    >>> key = parse_line(f'restrict,environment="LANG=C" ssh-ed25519 {blob} ana@laptop')
    >>> key.key_type, key.comment, len(key.key_bytes())
    ('ssh-ed25519', 'ana@laptop', 51)
    >>> key.has_flag("RESTRICT"), key.has_flag("pty"), key.environment()
    (True, False, {'LANG': 'C'})
    """

    key_type: str
    key_base64: str
    options: tuple[KeyOption, ...] = ()
    comment: str = ""

    def key_bytes(self) -> bytes:
        """Decode the base64 blob as OpenSSH does; raise :class:`AuthKeyError` if it is not base64.

        >>> from authkeyline import AuthorizedKey
        >>> AuthorizedKey("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5").key_bytes()
        b'\\x00\\x00\\x00\\x0bssh-ed25519'
        """
        return decode_base64(self.key_base64)

    def public_key(self) -> PublicKey:
        """Decode and check the blob; its type must agree with ``key_type``.

        Raises :class:`AuthKeyError` when the blob is not a valid key of that type. A record
        returned by :func:`parse_line` has passed this check already.

        >>> from authkeyline import AuthKeyError, AuthorizedKey
        >>> blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
        >>> AuthorizedKey("ssh-ed25519", blob).public_key().bits
        256
        >>> try:
        ...     AuthorizedKey("ecdsa-sha2-nistp256", blob).public_key()
        ... except AuthKeyError as error:
        ...     print(error)
        line says 'ecdsa-sha2-nistp256' but the key blob holds 'ssh-ed25519'
        """
        key = decode_key(self.key_bytes())
        check_type_agrees(self.key_type, key.key_type)
        return key

    def fingerprint(self, hash: Literal["sha256", "md5"] = "sha256") -> str:
        """The fingerprint of :meth:`public_key`, as ``ssh-keygen -l -E <hash>`` prints it.

        >>> from authkeyline import AuthorizedKey
        >>> blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
        >>> AuthorizedKey("ssh-ed25519", blob).fingerprint()
        'SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA'
        """
        return self.public_key().fingerprint(hash)

    def values(self, name: str) -> tuple[str, ...]:
        """The values of every option called ``name``, in order, compared case-insensitively.

        >>> from authkeyline import parse_line
        >>> blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
        >>> parse_line(f'permitopen="a:1",PermitOpen="b:2" ssh-ed25519 {blob}').values("permitopen")
        ('a:1', 'b:2')
        """
        wanted = require_str(name, "name").lower()
        return tuple(
            option.value
            for option in self.options
            if option.value is not None and option.name.lower() == wanted
        )

    def environment(self) -> dict[str, str]:
        """The ``environment`` options as a mapping; the first value of a name wins, as in sshd.

        >>> from authkeyline import AuthorizedKey, KeyOption
        >>> env = (KeyOption("environment", "A=1"), KeyOption("environment", "A=2"))
        >>> AuthorizedKey("ssh-ed25519", "", env).environment()
        {'A': '1'}
        """
        variables: dict[str, str] = {}
        for value in self.values("environment"):
            name, _, text = value.partition("=")
            variables.setdefault(name, text)
        return variables

    def has_flag(self, name: str) -> bool:
        """Whether the flag ``name`` (``restrict``, ``no-pty``) is written, case-insensitively.

        This looks at the names on the line, not at what they add up to: ``restrict`` does
        not make ``has_flag("no-pty")`` true.

        >>> from authkeyline import AuthorizedKey, KeyOption
        >>> key = AuthorizedKey("ssh-ed25519", "", (KeyOption("Restrict"),))
        >>> key.has_flag("restrict"), key.has_flag("no-pty")
        (True, False)
        """
        wanted = require_str(name, "name").lower()
        return any(o.value is None and o.name.lower() == wanted for o in self.options)
