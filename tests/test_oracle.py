"""ssh-keygen as the oracle: fresh throwaway keys, the listing must match it byte for byte.

Runs only when ``ssh-keygen`` is on the PATH. ``ssh-keygen -l`` skips the options field
without checking it, so it pins key types, blobs, sizes and fingerprints, not options.
"""

from __future__ import annotations

import contextlib
import io
import shutil
import subprocess
from pathlib import Path

import pytest
from keyfactory import b64, blob, ec_point, fields, mpint, string

from authkeyline import AuthKeyError, parse_line
from authkeyline._cli import main

KEYGEN = shutil.which("ssh-keygen")
pytestmark = pytest.mark.skipif(KEYGEN is None, reason="ssh-keygen is not on the PATH")


def keygen(*args: str | Path) -> subprocess.CompletedProcess[str]:
    assert KEYGEN is not None
    return subprocess.run(
        [KEYGEN, *map(str, args)], capture_output=True, text=True, check=False, timeout=120
    )


def listing(path: Path, hash: str) -> str:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert main(["-E", hash, str(path)]) == 0
    return out.getvalue()


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    folder = tmp_path_factory.mktemp("keys")
    kinds = {
        "ed": ["-t", "ed25519"],
        "e256": ["-t", "ecdsa", "-b", "256"],
        "e384": ["-t", "ecdsa", "-b", "384"],
        "e521": ["-t", "ecdsa", "-b", "521"],
        "r1024": ["-t", "rsa", "-b", "1024"],
        "r3072": ["-t", "rsa", "-b", "3072"],
    }
    for name, kind in kinds.items():
        made = keygen("-q", *kind, "-N", "", "-C", f"throwaway {name}", "-f", folder / name)
        assert made.returncode == 0, made.stderr
    for user in ("e256", "r1024"):
        signed = keygen("-q", "-s", folder / "ed", "-I", "id", "-n", "a,b", folder / f"{user}.pub")
        assert signed.returncode == 0, signed.stderr
    return folder


def test_listing_matches_ssh_keygen(generated: Path) -> None:
    lines = []
    for pub in sorted(generated.glob("*.pub")):
        text = pub.read_text().strip()
        lines.append(f'restrict,command="x, y" {text}' if "e384" in pub.name else text)
    parts = lines[0].split()
    lines.append(" ".join(parts[:2]))  # no comment
    lines.append(f"rsa-sha2-512 {b64(blob('ssh-rsa', 'rsa'))} sig-name")
    sk = "sk-ssh-ed25519@openssh.com"
    lines.append(f"{sk} {b64(blob(sk, 'ed25519-sk'))} security key")
    authorized = generated / "authorized_keys"
    authorized.write_text("# header\n" + "\n".join(lines) + "\n")
    for hash in ("sha256", "md5"):
        expected = keygen("-l", "-E", hash, "-f", authorized)
        assert expected.returncode == 0, expected.stderr
        assert listing(authorized, hash) == expected.stdout
    assert expected.stdout.count("\n") == len(lines) and "-CERT)" in expected.stdout


def test_padded_integers_fingerprint_like_ssh_keygen(tmp_path: Path) -> None:
    modulus = (1 << 2047) | int.from_bytes(bytes(range(1, 200)), "big")
    padded = string("ssh-rsa") + mpint(65537, pad=2) + mpint(modulus, pad=1)
    path = tmp_path / "padded"
    path.write_text(f"ssh-rsa {b64(padded)} c\n")
    expected = keygen("-l", "-f", path)
    assert expected.returncode == 0, expected.stderr
    assert listing(path, "sha256") == expected.stdout


def _rejected_blobs() -> list[tuple[str, bytes]]:
    point = ec_point("nistp256")
    curve = string("ecdsa-sha2-nistp256") + string("nistp256")
    return [
        ("ssh-ed25519", string("ssh-ed25519") + string(bytes(31))),
        ("ssh-ed25519", blob("ssh-ed25519", "ed25519") + b"\0"),
        ("ssh-rsa", blob("ssh-rsa", "rsa", bits=1023)),
        ("ssh-rsa", blob("ssh-ed25519", "ed25519")),
        ("ecdsa-sha2-nistp256", curve + string(point[:-1] + bytes([point[-1] ^ 1]))),
        ("ecdsa-sha2-nistp256", curve + string(point[:33])),
        ("ecdsa-sha2-nistp384", blob("ecdsa-sha2-nistp256", "ecdsa")),
        ("ecdsa-sha2-nistp256", string("ecdsa-sha2-nistp256") + fields("ecdsa", "nistp384")),
    ]


@pytest.mark.parametrize("case", range(len(_rejected_blobs())))
def test_ssh_keygen_and_the_parser_reject_the_same_blobs(case: int, tmp_path: Path) -> None:
    key_type, data = _rejected_blobs()[case]
    line = f"{key_type} {b64(data)} bad"
    path = tmp_path / "bad"
    path.write_text(line + "\n")
    assert keygen("-l", "-f", path).returncode != 0
    with pytest.raises(AuthKeyError):
        parse_line(line)
