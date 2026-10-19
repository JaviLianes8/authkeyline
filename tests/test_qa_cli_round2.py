"""Round 2 contracts of the command line: exit status, closed streams, tabs and escaping."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unicodedata
from pathlib import Path

import pytest

from authkeyline._cli import main
from authkeyline._listing import escape

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
KEY = f"ssh-ed25519 {BLOB}"
FP = "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA"
SRC = str(Path(__file__).resolve().parents[1] / "src")


def test_an_unreadable_file_then_a_broken_one_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.keys"
    bad.write_text("bogus\n")
    assert main([str(tmp_path / "missing.keys"), str(bad)]) == 2
    assert main(["--check", str(bad), str(tmp_path / "missing.keys")]) == 2
    assert f"{bad}:1: " in capsys.readouterr().err


class Gone:
    """A standard error whose reader has closed the pipe."""

    def write(self, text: str) -> int:
        raise BrokenPipeError(32, "Broken pipe")

    def flush(self) -> None:
        pass


@pytest.mark.parametrize("check", [[], ["--check"]], ids=["listing", "check"])
def test_a_closed_stderr_keeps_the_status_of_a_broken_line(
    check: list[str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bad = tmp_path / "bad.keys"
    bad.write_text("bogus\n")
    monkeypatch.setattr(sys, "stderr", Gone())
    assert main([*check, str(bad)]) == 1
    assert main([*check, str(tmp_path / "missing.keys")]) == 2


def test_stderr_piped_to_head_keeps_status_1(tmp_path: Path) -> None:
    path = tmp_path / "bad.keys"
    path.write_text("".join(f"junk{n}\n" for n in range(20_000)))
    for extra in ([], ["--check"]):
        process = subprocess.Popen(
            [sys.executable, "-m", "authkeyline", *extra, str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env={**os.environ, "PYTHONPATH": SRC},
        )
        assert process.stderr is not None
        process.stderr.readline()
        process.stderr.close()
        assert process.wait(timeout=120) == 1


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_a_closed_stream_is_skipped_and_the_status_kept(
    stream: str, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    good, bad = tmp_path / "good.keys", tmp_path / "bad.keys"
    good.write_text(f"{KEY} c\n")
    bad.write_text("bogus\n")
    monkeypatch.setattr(sys, stream, None)
    assert main([str(good)]) == 0
    assert main(["--json", str(good)]) == 0
    assert main([str(bad)]) == 1
    assert main([str(tmp_path / "missing.keys")]) == 2


def test_the_listing_splits_fields_at_tabs(
    tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    path = tmp_path / "keys"
    path.write_bytes(f"ssh-ed25519\t{BLOB}\tmy comment\nno-pty\t{KEY}\n".encode())
    assert main([str(path)]) == 0
    assert capsysbinary.readouterr().out == (
        f"256 {FP} my comment (ED25519)\n256 {FP} no-pty (ED25519)\n".encode()
    )


def test_json_file_names_are_valid_unicode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "k\udcff.keys"
    try:
        path.write_text(f"{KEY} c\n")
    except (OSError, UnicodeError):
        pytest.skip("this file system cannot hold a name that is not UTF-8")
    assert main(["--json", str(path)]) == 0
    text = capsys.readouterr().out
    text.encode("utf-8")  # no lone surrogate left
    (entry,) = json.loads(text)
    assert entry["file"].endswith("k\ufffd.keys")


# U+0378 has been unassigned in every Unicode version so far; the newer code points are
# escaped or not according to the Unicode database of the running Python (see GUIDE.md).
@pytest.mark.parametrize("char", ["\u0378", "\u1c89", "\U0001fae9", "\U0001cc00", "\U000105c0"])
def test_unassigned_code_points_follow_the_running_unicode_database(char: str) -> None:
    unassigned = unicodedata.category(char) == "Cn"
    expected = "".join(f"\\{b:03o}" for b in char.encode()) if unassigned else char
    assert escape(f"a{char}b") == f"a{expected}b"
    if char == "\u0378":
        assert escape("a\u0378b") == "a\\315\\270b"
