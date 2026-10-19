"""How the sshd oracle's output and the library's records are put side by side.

The harness prints, for an accepted line, what sshauthopt_parse recorded; :func:`model`
derives the same fields from an :class:`AuthorizedKey` by the rules of sshd(8).
"""

from __future__ import annotations

import re

from authkeyline import AuthorizedKey

TUNID_ANY = 0x7FFFFFFF  # misc.h SSH_TUNID_ANY
FLAG_FIELDS = {"port-forwarding": "port", "agent-forwarding": "agent", "x11-forwarding": "x11"}
FLAG_FIELDS |= {"pty": "pty", "user-rc": "userrc"}
NUMBERS: tuple[str, ...] = ("restricted", "port", "agent", "x11", "pty", "userrc")
NUMBERS += ("certauth", "notouch", "verify", "tun")


def unhex(field: str) -> str | None:
    if field == "-":
        return None
    return "" if field == "=" else bytes.fromhex(field).decode("utf-8", "surrogateescape")


def unhex_list(field: str) -> list[str]:
    return [] if field == "-" else [unhex(item) or "" for item in field.split(",")]


def model(key: AuthorizedKey) -> dict[str, object]:
    """What sshauthopt_parse records for the options of ``key``, derived from the record."""
    flags = {"port": 1, "agent": 1, "x11": 1, "pty": 1, "userrc": 1}
    state: dict[str, object] = {"restricted": 0, "certauth": 0, "notouch": 0, "verify": 0}
    for option in key.options:
        name = option.name.lower()
        if option.value is not None:
            continue
        on = 0 if name.startswith("no-") else 1
        bare = name[3:] if name.startswith("no-") else name
        if bare == "restrict":
            state["restricted"] = 1
            flags = dict.fromkeys(flags, 0)
        elif bare in FLAG_FIELDS:
            flags[FLAG_FIELDS[bare]] = on
        elif bare == "cert-authority":
            state["certauth"] = 1
        elif bare == "touch-required":
            state["notouch"] = 1 - on
        elif bare == "verify-required":
            state["verify"] = on
    tunnel = key.values("tunnel")  # the last one wins
    state["tun"] = (
        -1
        if not tunnel
        else (TUNID_ANY if tunnel[-1].lower() == "any" else int(tunnel[-1].strip()))
    )
    for name in ("command", "principals", "from"):
        state[name] = (key.values(name) or (None,))[0]
    state["env"] = [f"{k}={v}" for k, v in key.environment().items()]
    state["permitopen"] = list(key.values("permitopen"))
    state["permitlisten"] = [v if ":" in v else "*:" + v for v in key.values("permitlisten")]
    return {**flags, **state}


def observed(fields: list[str]) -> dict[str, object]:
    pairs = dict(item.split("=", 1) for item in fields[7:])
    found: dict[str, object] = {k: int(pairs[k]) for k in NUMBERS}
    for name in ("command", "principals", "from"):
        found[name] = unhex(pairs[name])
    for name in ("env", "permitopen", "permitlisten"):
        found[name] = unhex_list(pairs[name])
    return found


def plain_name(name: str) -> str:
    # sshkey_ssh_name gives the name of the key type, not the alias the blob used.
    return re.sub(r"^rsa-sha2-(256|512)", "ssh-rsa", name).removeprefix("webauthn-")


def by_service_name(fields: list[str]) -> bool:
    pairs = dict(item.split("=", 1) for item in fields[7:])
    targets = unhex_list(pairs["permitopen"]) + unhex_list(pairs["permitlisten"])
    return any(re.search(r"[A-Za-z]", re.split("[:/]", t)[-1]) for t in targets)
