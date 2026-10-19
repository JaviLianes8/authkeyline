"""Round 3 contracts: closed standard input, argparse output into a closed pipe, padding."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from authkeyline import AuthKeyError, parse_line
from authkeyline._cli import main

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
SRC = str(Path(__file__).resolve().parents[1] / "src")
ENV = {**os.environ, "PYTHONPATH": SRC}
CLOSED = "authkeyline: -: standard input is closed\n"


@pytest.mark.parametrize("argv", [[], ["-"], ["--check", "-"], ["--json", "-"]])
def test_a_closed_stdin_is_a_file_that_cannot_be_read(
    argv: list[str], capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "stdin", None)
    assert main(argv) == 2
    assert capsys.readouterr().err == CLOSED


def test_a_closed_stdin_after_a_good_file_keeps_its_listing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    good = tmp_path / "good.keys"
    good.write_text(f"ssh-ed25519 {BLOB} c\n")
    monkeypatch.setattr(sys, "stdin", None)
    assert main(["--json", str(good), "-"]) == 2
    out, err = capsys.readouterr()
    assert '"comment": "c"' in out and err == CLOSED


def test_a_closed_stdin_and_stderr_still_exit_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", None)
    monkeypatch.setattr(sys, "stderr", None)
    assert main(["-"]) == 2


_CLOSED_STDIN = (
    "import sys; sys.stdin = None; from authkeyline._cli import main; raise SystemExit(main())"
)


def test_a_closed_stdin_exits_2_without_a_traceback() -> None:
    done = subprocess.run(
        [sys.executable, "-c", _CLOSED_STDIN], capture_output=True, text=True, env=ENV, timeout=120
    )
    assert (done.returncode, done.stdout, done.stderr) == (2, "", CLOSED)


@pytest.mark.skipif(os.name != "posix", reason="closing fd 0 before exec needs POSIX")
def test_a_process_started_with_stdin_closed_exits_2() -> None:
    done = subprocess.run(
        [sys.executable, "-m", "authkeyline", "-"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=ENV,
        timeout=120,
        preexec_fn=lambda: os.close(0),
    )
    assert (done.returncode, done.stderr) == (2, CLOSED)


def _into_a_closed_pipe(args: list[str], *, merge: bool) -> tuple[int, bytes]:
    process = subprocess.Popen(
        [sys.executable, "-m", "authkeyline", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if merge else subprocess.PIPE,
        env=ENV,
    )
    assert process.stdout is not None
    process.stdout.close()  # the reader is gone before the parser writes anything
    process.stdout = None
    _, err = process.communicate(timeout=120)
    return process.returncode, err or b""


@pytest.mark.parametrize("merge", [True, False], ids=["2>&1", "stdout-only"])
def test_a_usage_error_into_a_closed_pipe_exits_2(merge: bool) -> None:
    status, err = _into_a_closed_pipe(["--bogus"], merge=merge)
    assert status == 2
    assert b"Traceback" not in err and b"Exception ignored" not in err


def test_help_into_a_closed_pipe_exits_0_quietly() -> None:
    assert _into_a_closed_pipe(["--help"], merge=False) == (0, b"")


def test_a_usage_error_with_stderr_closed_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stderr", None)
    with pytest.raises(SystemExit) as caught:
        main(["--bogus"])
    assert caught.value.code == 2


@pytest.mark.parametrize(
    "blob", ["AAAAC3Nz=", "AAAA=", "AAAA==", "AAAA===", "AAB==", f"{BLOB}=", "AB==AAAA", "=AAA"]
)
def test_misplaced_padding_gives_the_same_message_on_every_python(blob: str) -> None:
    with pytest.raises(AuthKeyError) as caught:
        parse_line(f"ssh-ed25519 {blob}")
    assert caught.value.reason.startswith("key blob is not valid base64")
