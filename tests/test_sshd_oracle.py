"""OpenSSH itself as the oracle: every line is read by sshd's own code and by the library.

``scripts/sshd-oracle/build.sh`` links ``harness.c`` against the pinned openssh-portable
commit; the harness reads lines the way sshd's authorized_keys loop does (sshkey_read,
sshkey_advance_past_options, sshauthopt_parse) and prints what it found. Set
``AUTHKEYLINE_SSHD_HARNESS`` to the command that runs it (for example
``wsl -d Ubuntu -e /path/harness``); without it these tests skip.

Two differences are documented in the README and allowed here: certificate signatures are
not verified, and ports given by service name in ``permitopen`` are refused.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest
from keyfactory import ed25519_line
from sshd_corpus import corpus
from sshd_model import by_service_name, model, observed, plain_name, unhex
from test_authopt import _cases as upstream_cases

from authkeyline import AuthKeyError, AuthorizedKey, parse_line
from authkeyline._codec import entries

HARNESS = os.environ.get("AUTHKEYLINE_SSHD_HARNESS", "")
pytestmark = pytest.mark.skipif(not HARNESS, reason="set AUTHKEYLINE_SSHD_HARNESS")
UPSTREAM = Path(__file__).parent / "upstream" / "authopt-tests.c"


def run_harness(lines: list[str]) -> list[str]:
    feed = "".join(text.encode("utf-8", "surrogateescape").hex() + "\n" for text in lines)
    done = subprocess.run(
        shlex.split(HARNESS), input=feed, capture_output=True, text=True, check=True, timeout=600
    )
    out = done.stdout.splitlines()
    assert len(out) == len(lines)
    return out


def compare(lines: list[str]) -> dict[str, int]:
    counts = {"accept": 0, "reject": 0, "blank": 0, "cert": 0, "service": 0}
    for text, verdict in zip(lines, run_harness(lines), strict=True):
        fields = verdict.split("\t")
        try:
            key: AuthorizedKey | None = parse_line(text)
            error = ""
        except AuthKeyError as exc:
            key, error = None, exc.reason
        if fields[0] == "BLANK":
            assert not entries(text), repr(text)
            counts["blank"] += 1
        elif fields[0] == "REJECT":
            if key is not None and key.public_key().certificate is not None:
                counts["cert"] += 1  # documented: the signature is not verified
                continue
            assert key is None, (text, verdict)
            counts["reject"] += 1
        else:
            if key is None and "needs a port" in error and by_service_name(fields):
                counts["service"] += 1  # documented: service names are refused
                continue
            assert key is not None, (text, verdict, error)
            public = key.public_key()
            got = [
                plain_name(public.key_type),
                public.short_type,
                str(public.bits),
                public.fingerprint(),
                public.fingerprint("md5"),
            ]
            assert got == fields[1:6], (text, verdict)
            assert key.comment == (unhex(fields[6]) or "").rstrip(" \t\r"), (text, verdict)
            assert model(key) == observed(fields), (text, verdict)
            counts["accept"] += 1
    return counts


def real_certificates(tmp_path: Path) -> list[str]:
    keygen = shutil.which("ssh-keygen")
    if keygen is None:
        return []
    made = []
    for ca, user in (("ed25519", "ecdsa"), ("rsa", "ed25519"), ("ecdsa", "rsa")):
        for name in (ca + "-ca", user + "-user"):
            kind = name.split("-")[0]
            subprocess.run(
                [keygen, "-q", "-t", kind, "-N", "", "-C", name, "-f", str(tmp_path / name)],
                check=True,
                stdin=subprocess.DEVNULL,
            )
        subprocess.run(
            [
                keygen,
                "-q",
                "-s",
                str(tmp_path / f"{ca}-ca"),
                "-I",
                "id",
                "-n",
                "a,b",
                "-O",
                "no-pty",
                str(tmp_path / f"{user}-user.pub"),
            ],
            check=True,
        )
        made.append((tmp_path / f"{user}-user-cert.pub").read_text().strip())
    return made


def upstream_options(base: str) -> list[str]:
    if not UPSTREAM.is_file():
        return []
    good, bad, _ = upstream_cases()
    return [f"{field} {base}" for field in good + bad]


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_the_library_reads_lines_as_sshd_does(seed: int, tmp_path: Path) -> None:
    lines = corpus(seed, 4000, [])
    if seed == 1:
        lines += upstream_options(ed25519_line())
    counts = compare(lines)
    assert counts["accept"] > 1000 and counts["reject"] > 1000, counts
    assert counts["cert"] > 50 and counts["service"] > 5 and counts["blank"] >= 4, counts


def test_upstream_option_cases_reach_the_oracle() -> None:
    if not UPSTREAM.is_file():
        pytest.skip("authopt-tests.c not fetched; run scripts/fetch_upstream.py")
    assert len(upstream_options("ssh-ed25519 AAAA")) == 54


def test_certificates_signed_by_ssh_keygen_read_alike(tmp_path: Path) -> None:
    made = real_certificates(tmp_path)
    if not made:
        pytest.skip("ssh-keygen is not on the PATH")
    restricted = [f'restrict,command="c" {line}' for line in made]
    assert compare(made + restricted)["accept"] == 6
