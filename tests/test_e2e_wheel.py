"""Build the wheel, install it in a throwaway venv and drive the installed package.

Slow and needs the build backend, so it runs only with AUTHKEYLINE_E2E=1.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
import venv
import zipfile
from pathlib import Path

import pytest
from keyfactory import b64, blob, certificate, ed25519_line

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "tests/upstream/MANIFEST.json"
HARNESS = "scripts/sshd-oracle/harness.c"

pytestmark = pytest.mark.skipif(
    os.environ.get("AUTHKEYLINE_E2E") != "1", reason="set AUTHKEYLINE_E2E=1 to build"
)

PROGRAM = r"""
import dataclasses, importlib.metadata, importlib.resources, sys
import authkeyline as ak

assert "site-packages" in ak.__file__, ak.__file__
assert importlib.metadata.version("authkeyline") == ak.__version__
assert importlib.resources.files("authkeyline").joinpath("py.typed").is_file()
good, cert, rsa = sys.argv[1:4]
key = ak.parse_line('restrict,command="a \\"b\\" c:\\\\x" ' + good)
assert key.options[1].value == 'a "b" c:\\\\x' and key.has_flag("RESTRICT")
assert ak.parse_line(ak.build_line(key)) == key
assert key.public_key().bits == 256 and key.fingerprint().startswith("SHA256:")
assert ak.parse_line(cert).public_key().certificate.principals == ("alice",)
assert ak.parse_line(rsa).public_key().short_type == "RSA"
assert ak.check_file(good + "\nbogus " + good) == [ak.LineProblem(2, "unknown option 'bogus'")]
assert "ssh-ed25519" in ak.KEY_TYPES
for call in (
    lambda: ak.parse_line("command=x " + good),
    lambda: ak.parse_line("ssh-rsa " + good.split()[1]),
    lambda: ak.build_line(dataclasses.replace(key, comment="x\nssh-ed25519 AAAA")),
    lambda: ak.build_line(dataclasses.replace(key, options=(ak.KeyOption("command", "a\\"),))),
):
    try:
        call()
    except ak.AuthKeyError as error:
        assert isinstance(error, ValueError)
    else:
        raise AssertionError("expected AuthKeyError")
print("e2e ok")
"""


def _run(
    *cmd: str | Path, cwd: Path | None = None, stdin: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(c) for c in cmd], cwd=cwd, input=stdin, capture_output=True, check=False
    )


def test_installed_wheel_end_to_end(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    built = _run(sys.executable, "-m", "build", "--outdir", dist, ROOT)
    assert built.returncode == 0, built.stderr
    (wheel,) = dist.glob("authkeyline-*.whl")
    version = wheel.name.split("-")[1]
    (sdist,) = dist.glob("authkeyline-*.tar.gz")
    names = zipfile.ZipFile(wheel).namelist()
    assert "authkeyline/py.typed" in names and "authkeyline/__main__.py" in names
    assert not any(name.startswith(("tests/", "scripts/")) for name in names)
    entry_points = next(name for name in names if name.endswith("entry_points.txt"))
    text = zipfile.ZipFile(wheel).read(entry_points).decode()
    assert "authkeyline = authkeyline._cli:main" in text
    with tarfile.open(sdist) as archive:
        # Paths inside the sdist, without its "authkeyline-<version>/" folder.
        files = {name.split("/", 1)[1] for name in archive.getnames() if "/" in name}
    assert not any(name.startswith(("IMPROVEMENTS-round", "CERT-1.0")) for name in files)
    assert {"GUIDE.md", "LICENSE", "tests/upstream/MANIFEST.json"} <= files
    assert {"tests/test_sources.py", "scripts/fetch_upstream.py"} <= files
    assert not any(name.startswith("tests/upstream/") for name in files - {MANIFEST})
    # Only the sshd oracle harness, our own code, ships as C; no fetched OpenSSH source does.
    assert {name for name in files if name.endswith((".c", ".h"))} == {HARNESS}

    env_dir = tmp_path / "venv"
    venv.create(env_dir, with_pip=True)
    bindir = env_dir / ("Scripts" if sys.platform == "win32" else "bin")
    python = bindir / "python"
    installed = _run(python, "-m", "pip", "install", "-q", wheel)
    assert installed.returncode == 0, installed.stderr

    good = ed25519_line("e2e key")
    cert = f"ssh-ed25519-cert-v01@openssh.com {b64(certificate())} c"
    rsa = f"rsa-sha2-256 {b64(blob('ssh-rsa', 'rsa'))}"
    # Run from an empty folder so the source tree cannot shadow the install.
    work = tmp_path / "work"
    work.mkdir()
    result = _run(python, "-I", "-c", PROGRAM, good, cert, rsa, cwd=work)
    assert result.returncode == 0, result.stderr
    assert result.stdout.decode().strip() == "e2e ok"

    script = bindir / ("authkeyline.exe" if sys.platform == "win32" else "authkeyline")
    for command in ([python, "-m", "authkeyline"], [script]):
        shown = _run(*command, cwd=work, stdin=f"# c\n{good}\n".encode())
        assert shown.returncode == 0, shown.stderr
        out = shown.stdout.decode()
        assert out.startswith("256 SHA256:") and out.rstrip().endswith("e2e key (ED25519)")
        failed = _run(*command, "--check", cwd=work, stdin=f"bogus {good}\n".encode())
        assert failed.returncode == 1 and b"-:1: unknown option 'bogus'" in failed.stderr
        listed = _run(*command, "--json", "-E", "md5", cwd=work, stdin=f"{cert}\n".encode())
        (entry,) = json.loads(listed.stdout)
        assert entry["certificate"]["principals"] == ["alice"] and entry["line"] == 1
        assert entry["fingerprint"].startswith("MD5:") and listed.returncode == 0
    metadata = zipfile.ZipFile(wheel).read(f"authkeyline-{version}.dist-info/METADATA").decode()
    assert "Classifier: Development Status :: 5 - Production/Stable" in metadata
    assert "Requires-Dist" not in metadata.split("Provides-Extra")[0]
