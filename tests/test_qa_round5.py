"""Round 5 contracts: every lone surrogate in a name or argument, at every boundary."""

from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from authkeyline import _cli
from authkeyline._cli import main
from authkeyline._streams import encode, native

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
SRC = str(Path(__file__).resolve().parents[1] / "src")
ENV = {**os.environ, "PYTHONPATH": SRC, "PYTHON_COLORS": "0", "COLUMNS": "100"}
WINDOWS = pytest.mark.skipif(os.name != "nt", reason="only Windows names hold any surrogate")
# Surrogates that stand for no byte anywhere, at both ends of each range.
UNPAIRED = ["\ud800", "\udbff", "\udc00", "\udc7f", "\udd00", "\udfff"]
# Surrogates that surrogateescape keeps for one byte, 0x80 and 0xFF.
BYTES = [("\udc80", b"\x80"), ("\udcff", b"\xff")]
BYTE_CHARS = [char for char, _ in BYTES]


def _shown(char: str) -> bytes:
    return f"\\u{ord(char):04x}".encode()


@pytest.fixture(autouse=True)
def _plain_argparse(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHON_COLORS", "0")
    monkeypatch.setenv("COLUMNS", "100")


def _streams(monkeypatch: pytest.MonkeyPatch) -> tuple[io.TextIOWrapper, io.TextIOWrapper]:
    out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    err = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    return out, err


def _bytes(stream: io.TextIOWrapper) -> bytes:
    stream.flush()
    value = stream.buffer
    assert isinstance(value, io.BytesIO)
    return value.getvalue()


def _usage_error(argv: list[str]) -> Any:
    with pytest.raises(SystemExit) as done:
        main(argv)
    return done.value.code


@pytest.mark.parametrize("char", UNPAIRED)
def test_encode_escapes_every_unpaired_surrogate(char: str) -> None:
    assert encode(f"a{char}b") == b"a" + _shown(char) + b"b"


@pytest.mark.parametrize(("char", "byte"), BYTES)
def test_encode_gives_back_the_byte_of_an_escaped_surrogate(char: str, byte: bytes) -> None:
    assert encode(f"a{char}b") == b"a" + byte + b"b"


def test_encode_escapes_every_unpaired_surrogate_of_a_string() -> None:
    assert encode("a\ud800b\udfffc\udc00") == b"a\\ud800b\\udfffc\\udc00"


@pytest.mark.parametrize("char", [*UNPAIRED, *BYTE_CHARS])
def test_a_windows_name_has_every_surrogate_escaped(char: str) -> None:
    assert native(f"a{char}b{char}", windows=True) == f"a\\u{ord(char):04x}b\\u{ord(char):04x}"


@pytest.mark.parametrize("char", [*UNPAIRED, *BYTE_CHARS])
def test_a_posix_name_is_left_for_encode(char: str) -> None:
    assert native(f"a{char}", windows=False) == f"a{char}"


@pytest.mark.parametrize("char", UNPAIRED)
def test_a_missing_file_with_an_unpaired_surrogate_is_escaped(
    char: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, err = _streams(monkeypatch)
    assert main([f"k{char}.keys"]) == 2
    assert _bytes(err).startswith(b"authkeyline: k" + _shown(char) + b".keys: ")


@pytest.mark.parametrize("char", UNPAIRED)
def test_a_usage_error_with_an_unpaired_surrogate_is_escaped(
    char: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    out, err = _streams(monkeypatch)
    assert _usage_error([f"--x{char}"]) == 2
    assert _bytes(err).endswith(b"unrecognized arguments: --x" + _shown(char) + b"\n")
    assert _bytes(out) == b""


def test_two_unpaired_surrogates_in_a_name_and_an_argument_are_escaped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, err = _streams(monkeypatch)
    assert main(["a\ud800b\udfff.keys"]) == 2
    assert _bytes(err).startswith(b"authkeyline: a\\ud800b\\udfff.keys: ")
    _, err = _streams(monkeypatch)
    assert _usage_error(["--a\ud800b\udfff"]) == 2
    assert _bytes(err).endswith(b"arguments: --a\\ud800b\\udfff\n")


@pytest.mark.parametrize(("char", "byte"), BYTES)
def test_a_posix_name_byte_is_echoed_byte_for_byte(
    char: str, byte: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_cli, "native", lambda text: native(text, windows=False))
    _, err = _streams(monkeypatch)
    assert main([f"k{char}.keys"]) == 2
    assert _bytes(err).startswith(b"authkeyline: k" + byte + b".keys: ")


@pytest.mark.parametrize(("char", "byte"), BYTES)
def test_a_line_byte_is_kept_in_line_base64(
    char: str, byte: bytes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = f"ssh-ed25519 {BLOB} c".encode() + byte
    path = tmp_path / "k.pub"
    path.write_bytes(raw + b"\n")
    out, _ = _streams(monkeypatch)
    assert main(["--json", str(path)]) == 0
    (entry,) = json.loads(_bytes(out))
    assert base64.b64decode(entry["line_base64"]) == raw
    assert entry["comment"] == "c\ufffd"


@WINDOWS
@pytest.mark.parametrize("char", [*UNPAIRED, *BYTE_CHARS])
def test_a_broken_windows_file_has_every_surrogate_escaped(
    char: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = tmp_path / f"bad{char}"
    bad.write_text("ssh-ed25519 AAAA=\n")
    _, err = _streams(monkeypatch)
    assert main([str(bad)]) == 1
    assert _bytes(err).startswith(str(tmp_path).encode() + b"\\bad" + _shown(char) + b":1: ")


@WINDOWS
@pytest.mark.parametrize("char", [*UNPAIRED, *BYTE_CHARS])
def test_json_windows_names_have_every_surrogate_escaped(
    char: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    good = tmp_path / f"ok{char}"
    good.write_text(f"ssh-ed25519 {BLOB} c\n")
    out, _ = _streams(monkeypatch)
    assert main(["--json", str(good)]) == 0
    assert json.loads(_bytes(out))[0]["file"].endswith("ok" + _shown(char).decode())


@WINDOWS
def test_two_windows_files_that_differ_in_a_surrogate_stay_distinct(tmp_path: Path) -> None:
    for char in BYTE_CHARS:
        (tmp_path / f"ok{char}").write_text(f"ssh-ed25519 {BLOB} c\n")
    bad = tmp_path / "bad\udc80"
    bad.write_text("ssh-ed25519 AAAA=\n")
    names = [str(tmp_path / f"ok{char}") for char in BYTE_CHARS]
    argv = [sys.executable, "-m", "authkeyline"]
    done = subprocess.run([*argv, "--json", *names], capture_output=True, env=ENV, timeout=120)
    files = [entry["file"] for entry in json.loads(done.stdout)]
    assert done.returncode == 0 and [f[-8:] for f in files] == ["ok\\udc80", "ok\\udcff"]
    done = subprocess.run(
        [*argv, str(bad), "nofile\udc80"], capture_output=True, env=ENV, timeout=120
    )
    assert done.returncode == 2 and b"bad\\udc80:1: key blob is not valid base64" in done.stderr
    assert done.stderr.endswith(b"authkeyline: nofile\\udc80: No such file or directory\n")
