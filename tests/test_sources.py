"""The tables in the code agree with the pinned sources in tests/upstream (see MANIFEST.json).

Run scripts/fetch_upstream.py first; without the files these tests skip.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from keyfactory import GENERATORS, b64, blob

from authkeyline import KEY_TYPES, parse_line
from authkeyline._blob import MLDSA44_ED25519_SIZE, RSA_MIN_BITS
from authkeyline._cert import MAX_PRINCIPALS
from authkeyline._curves import CURVES
from authkeyline._keytypes import KEY_TYPES as TABLE
from authkeyline._keytypes import short_name
from authkeyline._optrules import (
    ENV_MAX,
    NEGATABLE_FLAGS,
    PERMIT_MAX,
    PLAIN_FLAGS,
    TUNNEL_MAX,
    VALUED,
)
from authkeyline._wire import MAX_BIGNUM_BYTES

UPSTREAM = Path(__file__).parent / "upstream"


def source(name: str) -> str:
    path = UPSTREAM / name
    if not path.is_file():
        pytest.skip(f"{name} not fetched; run scripts/fetch_upstream.py")
    return path.read_text(encoding="utf-8")


def sshd_section() -> str:
    text = source("sshd.8")
    return text.split(".Sh AUTHORIZED_KEYS FILE FORMAT", 1)[1].split("\n.Sh ", 1)[0]


def test_every_key_type_sshd_lists_is_known() -> None:
    listed = re.findall(r"^\.It\n([a-z0-9@.-]+)$", sshd_section(), flags=re.MULTILINE)
    assert len(listed) == 8
    assert set(listed) <= KEY_TYPES


def test_option_list_matches_sshd() -> None:
    items = re.findall(r"^\.It Cm ([A-Za-z0-9-]+)(=?)", sshd_section(), flags=re.MULTILINE)
    valued = {name for name, eq in items if eq}
    flags = {name.lower() for name, eq in items if not eq}
    assert valued == VALUED
    every_flag = PLAIN_FLAGS | NEGATABLE_FLAGS | {f"no-{name}" for name in NEGATABLE_FLAGS}
    assert flags <= every_flag
    assert every_flag - flags == {"touch-required", "no-verify-required"}


def test_example_file_of_sshd_parses() -> None:
    example = sshd_section().split(".Bd -literal -offset 3n\n", 1)[1].split("\n.Ed", 1)[0]
    rsa = b64(blob("ssh-rsa", "rsa"))
    sk = b64(blob("sk-ecdsa-sha2-nistp256@openssh.com", "ecdsa-sk"))
    lines = [line for line in example.splitlines() if not line.startswith("#")]
    assert len(lines) == 9
    for line in lines:
        key = parse_line(line.replace("ssh-rsa ...", f"ssh-rsa {rsa}").replace(" ...", f" {sk}"))
        assert key.key_type in KEY_TYPES


def test_option_names_match_the_parser() -> None:
    text = source("auth-options.c")
    body = text.split("sshauthopt_parse(const char *opts", 1)[1].split("\n}\n", 1)[0]
    flags = dict(re.findall(r'opt_flag\("([a-z0-9-]+)", ([01])', body))
    assert {name for name, negate in flags.items() if negate == "0"} == PLAIN_FLAGS
    assert {name for name, negate in flags.items() if negate == "1"} == NEGATABLE_FLAGS
    assert set(re.findall(r'opt_match\(&opts, "([a-z-]+)"\)', body)) == VALUED


def test_key_type_table_matches_sshkey_c() -> None:
    names: dict[str, str] = {}
    for name in ("ssh-ed25519.c", "ssh-ed25519-sk.c", "ssh-ecdsa.c", "ssh-ecdsa-sk.c"):
        names |= _impls(source(name))
    names |= _impls(source("ssh-rsa.c")) | _impls(source("ssh-mldsa-eddsa.c"))
    assert set(names) == set(TABLE)
    for name, short in names.items():
        assert short_name(TABLE[name]) == short, name
    keyimpls = source("sshkey.c").split("keyimpls[] = {", 1)[1].split("};", 1)[0]
    assert keyimpls.count("&sshkey_") == len(TABLE)


def _impls(text: str) -> dict[str, str]:
    pairs = re.findall(r'\.name = \*/\s+"([^"]+)",\s+/\* \.shortname = \*/\s+"([^"]+)"', text)
    return dict(pairs)


def test_limits_match_the_headers() -> None:
    assert f"SSH_RSA_MINIMUM_MODULUS_SIZE\t{RSA_MIN_BITS}" in source("sshkey.h")
    assert f"SSHKEY_CERT_MAX_PRINCIPALS\t{MAX_PRINCIPALS}" in source("sshkey.h")
    crypto = source("crypto_api.h")
    assert f"MLDSA44_PUBLICKEYBYTES {MLDSA44_ED25519_SIZE - 32}" in crypto
    assert "crypto_sign_ed25519_PUBLICKEYBYTES 32U" in crypto
    options_h = source("auth-options.h")
    assert f"SSH_AUTHOPT_ENV_MAX\t{ENV_MAX}" in options_h
    assert f"SSH_AUTHOPT_PERMIT_MAX\t{PERMIT_MAX}" in options_h
    assert "SSH_TUNID_ANY\t\t0x7fffffff" in source("misc.h") and TUNNEL_MAX == 0x7FFFFFFF - 2
    assert f"SSHBUF_MAX_BIGNUM\t({MAX_BIGNUM_BYTES * 8} / 8)" in source("sshbuf.h")


def test_curve_constants_match_rfc_5903() -> None:
    text = source("rfc5903.txt")
    sections = re.split(r"\n3\.[123]\.  ", text.split("\n4.  ", 1)[0])[1:]
    labels = r"\n(Group Prime/Irreducible Polynomial|Group Curve b|gx|gy):?\n"
    for curve, section in zip(("nistp256", "nistp384", "nistp521"), sections, strict=True):
        values = {
            label: int("".join(re.findall(r"[0-9A-F]{4,8}", block)), 16)
            for label, block in re.findall(labels + r"((?: [0-9A-F ]+\n)+)", section)
        }
        assert values["Group Prime/Irreducible Polynomial"] == CURVES[curve].p
        assert values["Group Curve b"] == CURVES[curve].b
        assert (values["gx"], values["gy"]) == tuple(int(v, 16) for v in GENERATORS[curve])
