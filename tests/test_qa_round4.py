"""Round 4 contracts: usage with stderr closed and unpaired surrogates."""

from __future__ import annotations

import io
import json
import os
import subprocess
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


def test_a_usage_error_with_stderr_closed_leaves_stdout_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = _binary()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", None)
    assert _exit_status(["--json", "--bogus"]) == 2
    assert _bytes(out) == b""


def test_a_process_with_stderr_closed_writes_no_usage_to_stdout() -> None:
    script = "import sys; sys.stderr = None; from authkeyline._cli import main; main(['--bogus'])"
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, env=ENV, timeout=120)
    assert (done.returncode, done.stdout) == (2, b"")


def test_a_usage_error_goes_to_stderr_only_and_ends_with_a_newline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out, err = _streams(monkeypatch)
    assert _exit_status(["--bogus"]) == 2
    expected = USAGE + "authkeyline: error: unrecognized arguments: --bogus\n"
    assert (_bytes(out), _bytes(err)) == (b"", expected.encode())


def test_the_help_ends_with_one_newline(monkeypatch: pytest.MonkeyPatch) -> None:
    out, err = _streams(monkeypatch)
    assert _exit_status(["--help"]) == 0
    assert _bytes(out).endswith(b"\nthe arguments are wrong\n") and _bytes(err) == b""


def test_an_unpaired_surrogate_in_an_argument_is_escaped(monkeypatch: pytest.MonkeyPatch) -> None:
    out, err = _streams(monkeypatch)
    assert _exit_status(["--b\ud800gus"]) == 2
    assert _bytes(err).endswith(b"unrecognized arguments: --b\\ud800gus\n")
    assert _bytes(out) == b""


def test_a_missing_file_with_an_unpaired_surrogate_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, err = _streams(monkeypatch)
    assert main(["nofile\ud800"]) == 2
    assert _bytes(err).startswith(b"authkeyline: nofile\\ud800: ")


def test_a_name_with_a_nul_is_a_file_that_cannot_be_read(monkeypatch: pytest.MonkeyPatch) -> None:
    _, err = _streams(monkeypatch)
    assert main(["a\x00b"]) == 2
    assert _bytes(err) == b"authkeyline: a\x00b: invalid file name\n"


@WINDOWS
@pytest.mark.parametrize("check", [[], ["--check"]])
def test_a_broken_file_with_an_unpaired_surrogate_is_reported(
    check: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = tmp_path / "bad\ud800"
    bad.write_text("ssh-ed25519 AAAA=\n")
    _, err = _streams(monkeypatch)
    assert main([*check, str(bad)]) == 1
    assert _bytes(err).startswith(str(tmp_path).encode() + b"\\bad\\ud800:1: ")


@WINDOWS
def test_json_names_with_an_unpaired_surrogate_are_escaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    good = tmp_path / "k\ud800.pub"
    good.write_text(f"ssh-ed25519 {BLOB} c\n")
    out, _ = _streams(monkeypatch)
    assert main(["--json", str(good)]) == 0
    assert json.loads(_bytes(out))[0]["file"].endswith("k\\ud800.pub")


@WINDOWS
@pytest.mark.parametrize("argv", [["--b\ud800gus"], ["nofile\ud800"]])
def test_a_process_given_an_unpaired_surrogate_exits_2(argv: list[str]) -> None:
    done = subprocess.run(
        [sys.executable, "-m", "authkeyline", *argv], capture_output=True, env=ENV, timeout=120
    )
    assert done.returncode == 2 and b"Traceback" not in done.stderr
