"""Value rules of the valued options, as sshauthopt_parse and its helpers in misc.c apply them."""

from __future__ import annotations

import re

from ._errors import AuthKeyError, shown

# The flags of sshd(8); the second group also takes a "no-" prefix (opt_flag allow_negate).
PLAIN_FLAGS = frozenset({"restrict", "cert-authority"})
NEGATABLE_FLAGS = frozenset(
    {
        "port-forwarding",
        "agent-forwarding",
        "x11-forwarding",
        "touch-required",
        "verify-required",
        "pty",
        "user-rc",
    }
)
SINGLE_VALUED = frozenset({"command", "principals", "from"})
VALUED = SINGLE_VALUED | {"expiry-time", "environment", "permitopen", "permitlisten", "tunnel"}

# auth-options.h SSH_AUTHOPT_ENV_MAX and SSH_AUTHOPT_PERMIT_MAX; misc.h SSH_TUNID_MAX.
ENV_MAX = 1024
PERMIT_MAX = 4096
TUNNEL_MAX = 0x7FFFFFFF - 2
NI_MAXHOST = 1025

_ENV_NAME = re.compile(r"[A-Za-z0-9_]+\Z")
_DIGITS = re.compile(r"[0-9]+\Z")
# strtonum (through strtoll) takes leading C whitespace and a sign before the digits.
_STRTONUM = re.compile(r"[ \t\n\v\f\r]*([+-]?)([0-9]+)\Z")
# Characters that stand for one undecodable byte of a file read with surrogateescape.
_ESCAPED_BYTE = re.compile("[\udc80-\udcff]")
_TIME_RANGES = ((4, 6, 1, 12), (6, 8, 1, 31), (8, 10, 0, 23), (10, 12, 0, 59), (12, 14, 0, 60))


def flag_name(name: str) -> str | None:
    """The canonical flag a name spells, or None when it is not a flag."""
    lower = name.lower()
    if lower in PLAIN_FLAGS or lower in NEGATABLE_FLAGS:
        return lower
    if lower.startswith("no-") and lower[3:] in NEGATABLE_FLAGS:
        return lower
    return None


def check_value(name: str, value: str) -> None:
    """Raise AuthKeyError when sshd would refuse ``value`` for the valued option ``name``."""
    if name == "environment":
        # The value may be a secret, so messages name the variable only.
        env_name, sep, _ = value.partition("=")
        if not sep:
            raise AuthKeyError("environment value is not NAME=value")
        if not _ENV_NAME.match(env_name):
            raise AuthKeyError(f"environment name {shown(env_name)} is not letters, digits and _")
    elif name in ("permitopen", "permitlisten"):
        _check_permit(name, value)
    elif name == "tunnel":
        if value.lower() != "any" and not _number_in(value, 0, TUNNEL_MAX):
            raise AuthKeyError(f"tunnel={shown(value)} is not a device number or 'any'")
    elif name == "expiry-time":
        _check_time(value)


def _check_permit(name: str, written: str) -> None:
    value = written
    if name == "permitlisten" and ":" not in value:
        value = "*:" + value  # a bare port listens on every address
    if value.startswith("["):
        close = value.find("]")
        if close < 0:
            raise AuthKeyError(f"{name}={shown(written)} has an unclosed IPv6 bracket")
        host, rest = value[: close + 1], value[close + 1 :]
        if rest[:1] not in (":", "/"):
            raise AuthKeyError(f"{name}={shown(written)} needs host:port")
        port = rest[1:]
    else:
        cut = re.search(r"[:/]", value)
        if cut is None:
            raise AuthKeyError(f"{name}={shown(written)} needs host:port")
        host, port = value[: cut.start()], value[cut.end() :]
    if _byte_length(host) >= NI_MAXHOST:
        raise AuthKeyError(f"{name} host name is too long")
    if port != "*" and not _number_in(port, 1, 65535):
        raise AuthKeyError(f"{name}={shown(written)} needs a port from 1 to 65535 or *")


def _byte_length(text: str) -> int:
    """Length in bytes of the line text sshd sees: UTF-8, one byte per escaped byte."""
    return len(text.encode("utf-8", "surrogatepass")) - 2 * len(_ESCAPED_BYTE.findall(text))


def _number_in(text: str, low: int, high: int) -> bool:
    match = _STRTONUM.match(text)
    if match is None:
        return False
    digits = match.group(2).lstrip("0") or "0"
    # strtonum refuses anything out of range; more digits than that never fit, and
    # converting them could hit Python's integer string limit.
    if len(digits) > len(str(high)):
        return False
    number = -int(digits) if match.group(1) == "-" else int(digits)
    return low <= number <= high


def _check_time(value: str) -> None:
    text, utc = value, False
    if len(text) > 1 and text[-1] in "zZ":
        text, utc = text[:-1], True
    elif len(text) > 3 and text[-3:].upper() == "UTC":
        text, utc = text[:-3], True
    if len(text) not in (8, 12, 14) or not _DIGITS.match(text):
        message = "is not YYYYMMDD[Z] or YYYYMMDDHHMM[SS][Z]"
        raise AuthKeyError(f"expiry-time={shown(value)} {message}")
    for start, end, low, high in _TIME_RANGES:
        if end <= len(text) and not low <= int(text[start:end]) <= high:
            raise AuthKeyError(f"expiry-time={shown(value)} is out of range")
    if utc and text.ljust(14, "0") == "19700101000000":
        raise AuthKeyError(f"expiry-time={shown(value)} is the epoch, which sshd refuses")
