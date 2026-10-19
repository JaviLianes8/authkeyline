"""Write a record back as one authorized_keys line that cannot be steered."""

from __future__ import annotations

from ._codec import parse_line
from ._errors import AuthKeyError, shown, type_name
from ._keytypes import KEY_TYPES
from ._model import AuthorizedKey, KeyOption
from ._optrules import VALUED, flag_name


def build_line(key: AuthorizedKey) -> str:
    """Render an :class:`AuthorizedKey` as one line, refusing anything that would not read back.

    Option names must be known flags or valued options, values cannot hold NUL, CR or LF or
    end with a backslash, the comment cannot hold them either (sshd would cut or ignore
    them, so a written line keeps to plain text), and the result must parse back to the
    same record. Raises :class:`AuthKeyError` for any of those, and ``TypeError`` when
    ``key`` is not an :class:`AuthorizedKey` or one of its fields has the wrong type
    (``options`` must be a tuple of :class:`KeyOption`).

    >>> from authkeyline import AuthorizedKey, KeyOption, build_line
    >>> blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
    >>> key = AuthorizedKey("ssh-ed25519", blob, (KeyOption("restrict"),), "ci")
    >>> build_line(key) == f"restrict ssh-ed25519 {blob} ci"
    True
    """
    _check_types(key)
    if key.key_type not in KEY_TYPES:
        raise AuthKeyError(f"unsupported key type {shown(key.key_type)}")
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


def _check_types(key: object) -> None:
    if not isinstance(key, AuthorizedKey):
        raise TypeError(f"key must be an AuthorizedKey, not {type_name(key)}")
    for field in ("key_type", "key_base64", "comment"):
        if not isinstance(getattr(key, field), str):
            raise TypeError(f"{field} must be a str, not {type_name(getattr(key, field))}")
    if not isinstance(key.options, tuple):
        raise TypeError(f"options must be a tuple, not {type_name(key.options)}")
    for option in key.options:
        if not isinstance(option, KeyOption):
            raise TypeError(f"options must hold KeyOption items, not {type_name(option)}")
        if not isinstance(option.name, str):
            raise TypeError(f"an option name must be a str, not {type_name(option.name)}")
        if option.value is not None and not isinstance(option.value, str):
            raise TypeError(f"an option value must be a str or None, not {type_name(option.value)}")


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
