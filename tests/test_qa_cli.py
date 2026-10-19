"""The command line: the comment column of ssh-keygen -l, escaping, help, pipes and JSON."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from keyfactory import b64, blob, certificate

from authkeyline import parse_line
from authkeyline._cli import main

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
KEY = f"ssh-ed25519 {BLOB}"
FP = "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA"
SRC = str(Path(__file__).resolve().parents[1] / "src")


def listed(raw: bytes, tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]) -> bytes:
    path = tmp_path / "keys"
    path.write_bytes(raw + b"\n")
    assert main([str(path)]) == 0
    out: bytes = capsysbinary.readouterr().out
    assert out.startswith(f"256 {FP} ".encode()) and out.endswith(b" (ED25519)\n")
    return out[len(f"256 {FP} ") : -len(" (ED25519)\n")]


# Written from do_fingerprint in ssh-keygen.c and vasnmprintf in utf8.c (openssh-portable
# 773771be); tests/test_oracle.py compares the same cases with a real ssh-keygen.
COMMENTS = [
    (f"no-pty {KEY}", "no-pty"),
    (f'restrict,command="a b" {KEY}', 'restrict,command="a b"'),
    (f'command="x \\" y" {KEY} c', "c"),
    (f"{KEY} #note", "no comment"),
    (f"no-pty {KEY} #note", "no-pty"),
    (f"{KEY} tail  ", "tail  "),
    (f"{KEY} a\tb\t", "a\tb\t"),
    (f"{KEY} a\rb", "a"),
    (f"{KEY}\r", "no comment"),
    (f"no-pty  {KEY} x", "x"),
    (f"no-pty  {KEY}", "no-pty"),
    (f"{KEY} esc\x1b[31mred\x07\x7f", "esc\\033[31mred\\007\\177"),
    (f"{KEY} c\x0bd \x85 \u2028", "c\\013d \\302\\205 \\342\\200\\250"),
    (f"{KEY} caf\xe9 \xe1rbol \u20ac", "caf\xe9 \xe1rbol \u20ac"),
]


@pytest.mark.parametrize(("line", "shown"), COMMENTS, ids=range(len(COMMENTS)))
def test_listing_shows_the_comment_as_ssh_keygen_does(
    line: str, shown: str, tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    assert listed(line.encode(), tmp_path, capsysbinary) == shown.encode()


def test_bytes_that_are_not_utf8_are_escaped_in_octal(
    tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    raw = KEY.encode() + b" caf\xe9 \xff \xed\xa0\x80 \\x"
    assert listed(raw, tmp_path, capsysbinary) == b"caf\\351 \\377 \\355\\240\\200 \\x"


def test_help_describes_every_option_and_usage_errors_exit_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["--help"])
    assert stopped.value.code == 0
    text = capsys.readouterr().out
    assert "-E {sha256,md5}  fingerprint hash" in text and "exit status" in text
    with pytest.raises(SystemExit) as stopped:
        main(["-E", "sha1", "k.pub"])
    assert stopped.value.code == 2


def test_a_closed_output_pipe_ends_quietly(tmp_path: Path) -> None:
    path = tmp_path / "many"
    path.write_text("".join(f"{KEY} key {n}\n" for n in range(20_000)))
    for extra in ([], ["--json"]):
        process = subprocess.Popen(
            [sys.executable, "-m", "authkeyline", *extra, str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # The package as tested, also when it is not installed.
            env={**os.environ, "PYTHONPATH": SRC},
        )
        assert process.stdout is not None and process.stderr is not None
        process.stdout.readline()
        process.stdout.close()
        error = process.stderr.read()
        process.stderr.close()
        assert process.wait(timeout=120) == 0
        assert error == b""


def test_json_is_valid_unicode_and_keeps_the_exact_bytes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "keys"
    odd = f'command="x\xe9" {KEY} caf'.encode("latin-1") + b"\xe9\n"
    path.write_bytes(f"{KEY} plain\n".encode() + odd)
    assert main(["--json", str(path)]) == 0
    text = capsys.readouterr().out
    text.encode("utf-8")  # no lone surrogate left
    first, second = json.loads(text)
    assert "line_base64" not in first and first["comment"] == "plain"
    assert second["comment"] == "caf\ufffd" and second["options"] == [["command", "x\ufffd"]]
    assert base64.b64decode(second["line_base64"]) == odd[:-1]


def test_json_certificate_ca_fingerprint_follows_the_hash(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ca = blob("ssh-ed25519", "ed25519")
    line = f"ssh-ed25519-cert-v01@openssh.com {b64(certificate(ca=ca))}"
    path = tmp_path / "keys"
    path.write_text(line + "\n")
    assert main(["-E", "md5", "--json", str(path)]) == 0
    (entry,) = json.loads(capsys.readouterr().out)
    ca_key = parse_line(line).public_key().certificate
    assert ca_key is not None
    assert entry["certificate"]["ca_fingerprint"] == ca_key.ca_key.fingerprint("md5")
    assert entry["fingerprint"].startswith("MD5:")
