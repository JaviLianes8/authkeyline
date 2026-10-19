"""Seeded authorized_keys lines for the sshd oracle: valid keys, hostile options, broken blobs.

Every line is built by hand from the grammar of sshd(8) and the blob layouts; nothing here
is copied from a third-party corpus. The generator is deterministic for a seed, apart from
the key material, which keyfactory draws at random.
"""

from __future__ import annotations

import base64
import random

from keyfactory import b64, blob, certificate, fields, string


def words(spec: str) -> list[str]:
    return spec.split("|")


FLAGS = words("restrict|cert-authority|port-forwarding|agent-forwarding|x11-forwarding")
FLAGS += words("touch-required|verify-required|pty|user-rc")
VALUED = words("command|principals|from|expiry-time|environment|permitopen|permitlisten|tunnel")
# Values near the edges of each rule.
VALUES = {
    "environment": words('A=1|A=2|B_2=x y|=x|A|A-B=1|a=|Z9=\\|A="q"'),
    "permitopen": words(
        "h:22|h:0|h:65535|h:65536|h:*|h:+1|h: 1|h:-1|h:|[::1]:22|[::1]/22|[::1|h/22|h"
        "|*:*|h:0x1|:22|h:22:1|h:ssh|h:http|h:nosuchservice"
    ),
    "permitlisten": words("22|*:22|0|h:1|[::1]:2|localhost:65535|65536|+5|ssh"),
    "tunnel": words("any|ANY|0|2147483645|2147483646|-1|+3| 3|x||07"),
    "expiry-time": words(
        "20300101|203001011200|20300101120000|20300101Z|20300101UTC|19700101Z"
        "|19700101000000Z|20301301|2030010|20300132|20300101240000|20300101125961"
        "|20300101125962|2030010112|z"
    ),
}
TEXT = 'ab ,=:*\\"#\t/x.'


def text(rng: random.Random, limit: int = 8) -> str:
    return "".join(rng.choice(TEXT) for _ in range(rng.randrange(limit)))


def option(rng: random.Random) -> str:
    roll = rng.random()
    if roll < 0.35:
        name = rng.choice(FLAGS)
        name = ("no-" + name) if rng.random() < 0.3 else name
        return name.upper() if rng.random() < 0.1 else name
    if roll < 0.9:
        name = rng.choice(VALUED)
        pool = VALUES.get(name)
        value = rng.choice(pool) if pool and rng.random() < 0.85 else text(rng)
        quoted = '"' + value.replace('"', '\\"') + '"' if rng.random() < 0.93 else value
        return f"{name}={quoted}"
    junk = ["bogus", "no-restrict", "", "pty=1", 'command"x"', "Port-Forwarding"]
    return rng.choice([*junk, "no-cert-authority", "ssh-ed25519", text(rng, 4)])


def options(rng: random.Random) -> str:
    count = rng.choice([0, 0, 1, 1, 2, 3, 5])
    parts = [option(rng) for _ in range(count)]
    joined = ",".join(parts)
    if joined and rng.random() < 0.05:
        joined += rng.choice([",", ", ", ",,x", '"'])
    return joined


def keys() -> list[tuple[str, bytes]]:
    """One fresh key of every plain type, two certificates, and RSA under its other names."""
    rsa = blob("ssh-rsa", "rsa")
    found = [
        ("ssh-ed25519", blob("ssh-ed25519", "ed25519")),
        ("ssh-rsa", rsa),
        ("rsa-sha2-256", rsa),
        ("rsa-sha2-512", rsa),
        ("ssh-rsa", blob("ssh-rsa", "rsa", bits=1024)),
        ("sk-ssh-ed25519@openssh.com", blob("sk-ssh-ed25519@openssh.com", "ed25519-sk")),
        ("ssh-mldsa44-ed25519", blob("ssh-mldsa44-ed25519", "mldsa44-ed25519")),
        ("ssh-ed25519-cert-v01@openssh.com", certificate()),
    ]
    for curve in ("nistp256", "nistp384", "nistp521"):
        name = f"ecdsa-sha2-{curve}"
        found.append((name, string(name) + fields("ecdsa", curve)))
    for name in (
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
    ):
        found.append((name, string(name) + fields("ecdsa-sk")))
    return found


def broken_blob(rng: random.Random, raw: bytes) -> str:
    """The base64 of ``raw`` after one random change, or a damaged base64 text."""
    roll = rng.randrange(9)
    data = bytearray(raw)
    if roll == 0:
        data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
    elif roll == 1:
        del data[rng.randrange(len(data)) :]
    elif roll == 2:
        data += bytes([rng.randrange(256)])
    elif roll == 3:
        at = rng.randrange(0, len(data) - 4)
        data[at : at + 4] = rng.randrange(2**32).to_bytes(4, "big")
    encoded = base64.b64encode(bytes(data)).decode()
    if roll == 4:
        cut = rng.randrange(len(encoded))
        encoded = encoded[:cut] + encoded[cut + 1 :]
    elif roll == 5:
        cut = rng.randrange(len(encoded))
        encoded = encoded[:cut] + rng.choice("\v\f\r=-_!") + encoded[cut:]
    elif roll == 6:
        encoded = encoded.rstrip("=")
    elif roll == 7 and encoded.endswith("="):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        last = encoded.rstrip("=")
        spare = alphabet[alphabet.index(last[-1]) ^ 1]
        encoded = last[:-1] + spare + encoded[len(last) :]
    return encoded


def comment(rng: random.Random) -> str:
    notes = ["", "", "user@host", "a  b", "x\t", "c\r", "x \r", "été", "#hash"]
    return rng.choice([*notes, "nul\0cut", " lead", text(rng, 12)])


def line(rng: random.Random, pool: list[tuple[str, bytes]]) -> str:
    key_type, raw = rng.choice(pool)
    if rng.random() < 0.05:
        key_type = rng.choice(pool)[0]  # a type that may not match the blob
    encoded = broken_blob(rng, raw) if rng.random() < 0.3 else b64(raw)
    head = options(rng)
    sep = rng.choice([" ", " ", "\t", "  "])
    parts = [head + sep if head else "", key_type, rng.choice([" ", "\t"]), encoded]
    note = comment(rng)
    if note:
        parts += [rng.choice([" ", "\t", "  "]), note]
    prefix = rng.choice(["", "", "", " ", "\t"])
    return prefix + "".join(parts)


def corpus(seed: int, count: int, extra: list[str]) -> list[str]:
    rng = random.Random(seed)
    pool = keys()
    shapes = ["", " ", "\t", "#", " # x", "\r", "\v", "\0", "x", "ssh-ed25519", "restrict"]
    lines = [*extra, *shapes, *(line(rng, pool) for _ in range(count))]
    return lines
