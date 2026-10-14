"""Read the options field exactly as sshauthopt_parse walks it."""

from __future__ import annotations

from ._errors import AuthKeyError
from ._model import KeyOption
from ._optrules import (
    ENV_MAX,
    PERMIT_MAX,
    SINGLE_VALUED,
    VALUED,
    check_value,
    flag_name,
)

_END = " \t"


def read_options(text: str) -> tuple[tuple[KeyOption, ...], int]:
    """Parse options from the start of ``text``; return them and the offset where they end.

    Like sshd, an empty element between commas is skipped and a comma followed by
    whitespace ends the field; a comma at the very end is an error.
    """
    options: list[KeyOption] = []
    pos = 0
    while pos < len(text) and text[pos] not in _END:
        if text[pos] != ",":
            option, pos = _read_one(text, pos)
            options.append(option)
            if pos == len(text) or text[pos] in _END:
                break
            if text[pos] != ",":
                raise AuthKeyError(f"unexpected {text[pos]!r} after option {option.name!r}")
        pos += 1
        if pos == len(text):
            raise AuthKeyError("options end with a comma")
    check_options(options)
    return tuple(options), pos


def _read_one(text: str, pos: int) -> tuple[KeyOption, int]:
    end = pos
    while end < len(text) and text[end] not in ',= \t"':
        end += 1
    name = text[pos:end]
    if end < len(text) and text[end] == "=":
        if name.lower() not in VALUED:
            raise AuthKeyError(f"unknown option {name!r}" if name else "empty option name")
        value, end = dequote(text, end + 1, name)
        return KeyOption(name, value), end
    if flag_name(name) is None:
        raise AuthKeyError(f"unknown option {name!r}" if name else f"unexpected {text[pos]!r}")
    return KeyOption(name), end


def dequote(text: str, pos: int, name: str) -> tuple[str, int]:
    """opt_dequote: a backslash escapes only a double quote and is otherwise kept."""
    if pos >= len(text) or text[pos] != '"':
        raise AuthKeyError(f"value of {name!r} must be in double quotes")
    out: list[str] = []
    pos += 1
    while pos < len(text) and text[pos] != '"':
        if text[pos] == "\\" and text[pos + 1 : pos + 2] == '"':
            pos += 1
        out.append(text[pos])
        pos += 1
    if pos >= len(text):
        raise AuthKeyError(f"value of {name!r} has no closing quote")
    return "".join(out), pos + 1


def check_options(options: list[KeyOption]) -> None:
    """The rules across options: single-use names, value formats, sshd's count limits."""
    seen: set[str] = set()
    env_names: set[str] = set()
    permits = {"permitopen": 0, "permitlisten": 0}
    for option in options:
        name = option.name.lower()
        if option.value is None:
            if flag_name(name) is None:
                raise AuthKeyError(f"option {option.name!r} needs a value")
            continue
        if name not in VALUED:
            raise AuthKeyError(f"option {option.name!r} takes no value")
        if name in SINGLE_VALUED and name in seen:
            raise AuthKeyError(f"option {name!r} appears more than once")
        seen.add(name)
        if name == "environment" and len(env_names) > ENV_MAX:
            raise AuthKeyError("too many environment options")
        if name in permits:
            if permits[name] > PERMIT_MAX:
                raise AuthKeyError(f"too many {name} options")
            permits[name] += 1
        check_value(name, option.value)
        if name == "environment":
            env_names.add(option.value.partition("=")[0])
