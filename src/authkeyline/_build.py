"""Write a record back as one authorized_keys line that cannot be steered."""

from __future__ import annotations

from ._codec import parse_line
from ._errors import AuthKeyError, shown, unsupported_type
from ._keytypes import KEY_TYPES
from ._model import AuthorizedKey, KeyOption, plain
from ._optrules import VALUED, flag_name


def build_line(key: AuthorizedKey) -> str:
    """Render an :class:`AuthorizedKey` as one line, refusing anything that would not read back.

    Option names must be known flags or valued options, values cannot hold NUL, CR or LF or
    end with a backslash, the comment cannot hold them either (sshd would cut or ignore
    them, so a written line keeps to plain text), and the result must parse back to the
    same record. Raises :class:`AuthKeyError` for any of those, and ``TypeError`` when
    ``key`` is not an :class:`AuthorizedKey` or one of its fields has the wrong type
    (``options`` must be a tuple of :class:`KeyOption`). ``str`` subclasses are read as
    plain text, and the line returned is a plain ``str``.

    >>> from authkeyline import AuthorizedKey, KeyOption, build_line
    >>> blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
    >>> key = AuthorizedKey("ssh-ed25519", blob, (KeyOption("restrict"),), "ci")
    >>> build_line(key) == f"restrict ssh-ed25519 {blob} ci"
    True
    """
    key = plain(key)
    if key.key_type not in KEY_TYPES:
        raise unsupported_type(key.key_type)
    if not key.key_base64 or any(char in key.key_base64 for char in " \t\r\n\0"):
        raise AuthKeyError("key blob must be one base64 word")
    fields = []
    if key.options:
        fields.append(",".join(_build_option(option) for option in key.options))
    fields += [key.key_type, key.key_base64]
    if key.comment:
        if any(char in key.comment for char in "\0\r\n"):
            raise AuthKeyError("comment holds a NUL or a line break")
        fields.append(key.comment)
    line = " ".join(fields)
    if parse_line(line) != key:
        raise AuthKeyError("the record does not read back the same; check the fields' spacing")
    return line


def _build_option(option: KeyOption) -> str:
    name = option.name
    if option.value is None:
        if flag_name(name) is None:
            raise AuthKeyError(f"{shown(name)} is not a flag option")
        return name
    if name.lower() not in VALUED:
        raise AuthKeyError(f"{shown(name)} is not a valued option")
    value = option.value
    if any(char in value for char in "\0\r\n"):
        raise AuthKeyError(f"value of {shown(name)} holds a NUL or a line break")
    if value.endswith("\\"):
        raise AuthKeyError(f"value of {shown(name)} ends with a backslash, which sshd cannot read")
    return name + '="' + value.replace('"', '\\"') + '"'
