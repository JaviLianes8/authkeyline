"""Round 4 contracts for the output writer: raw bytes, text-only streams, errors, order."""

from __future__ import annotations

import errno
import io
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from authkeyline._cli import main

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
SRC = str(Path(__file__).resolve().parents[1] / "src")
ENV = {**os.environ, "PYTHONPATH": SRC, "PYTHON_COLORS": "0", "COLUMNS": "100"}
USAGE = "usage: authkeyline [-h] [-E {sha256,md5}] [--json] [--check] [FILE ...]\n"
WINDOWS = pytest.mark.skipif(os.name != "nt", reason="only Windows file names hold U+D800")


@pytest.fixture(autouse=True)
def _plain_argparse(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHON_COLORS", "0")
    monkeypatch.setenv("COLUMNS", "100")


def _binary() -> io.TextIOWrapper:
    return io.TextIOWrapper(io.BytesIO(), encoding="utf-8")


def _bytes(stream: io.TextIOWrapper) -> bytes:
    stream.flush()
    value = stream.buffer
    assert isinstance(value, io.BytesIO)
    return value.getvalue()


def _streams(monkeypatch: pytest.MonkeyPatch) -> tuple[io.TextIOWrapper, io.TextIOWrapper]:
    out, err = _binary(), _binary()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    return out, err


def _exit_status(argv: list[str]) -> Any:
    with pytest.raises(SystemExit) as done:
        main(argv)
    return done.value.code


def test_a_missing_name_that_is_not_utf8_is_echoed_byte_for_byte(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, err = _streams(monkeypatch)
    assert main(["k\udcff.keys"]) == 2
    assert _bytes(err).startswith(b"authkeyline: k\xff.keys: ")


def test_a_broken_name_that_is_not_utf8_is_echoed_byte_for_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = tmp_path / "bad\udcff"
    bad.write_text("ssh-ed25519 AAAA=\n")
    _, err = _streams(monkeypatch)
    assert main([str(bad)]) == 1
    assert b"bad\xff:1: " in _bytes(err)


def test_a_text_only_stream_gets_the_name_as_it_came(monkeypatch: pytest.MonkeyPatch) -> None:
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    assert main(["k\udcff.keys"]) == 2
    assert err.getvalue().startswith("authkeyline: k\udcff.keys: ")


class _TextOnly(io.StringIO):
    """A stream without a byte buffer whose reader has gone: flushing it fails."""

    flushes = 0

    def flush(self) -> None:
        self.flushes += 1
        raise BrokenPipeError(errno.EPIPE, "Broken pipe")


def test_a_text_only_stream_is_flushed_under_the_reader_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = _TextOnly()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", io.StringIO())  # nothing real for the null device
    assert _exit_status(["--help"]) == 0
    assert out.flushes == 1


class _Failing(io.BytesIO):
    """A byte buffer whose every write fails with one errno."""

    def __init__(self, code: int) -> None:
        super().__init__()
        self.code = code

    def write(self, data: Any) -> int:
        raise OSError(self.code, os.strerror(self.code))


@pytest.mark.parametrize("code", [errno.ENOSPC, errno.EIO])
def test_an_output_error_that_is_not_a_closed_reader_is_raised(
    code: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    good = tmp_path / "good.keys"
    good.write_text(f"ssh-ed25519 {BLOB} c\n")
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(_Failing(code), encoding="utf-8"))
    with pytest.raises(OSError) as raised:
        main([str(good)])
    assert raised.value.errno == code


def test_text_already_waiting_on_stdout_comes_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    good = tmp_path / "good.keys"
    good.write_text(f"ssh-ed25519 {BLOB} c\n")
    out = _binary()
    monkeypatch.setattr(sys, "stdout", out)
    out.write("FIRST")
    assert main([str(good)]) == 0
    assert _bytes(out).startswith(b"FIRST256 SHA256:")
