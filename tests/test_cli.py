"""The command line lists keys like ssh-keygen -l, prints JSON, and exits 1 on broken lines."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from keyfactory import b64, certificate, ed25519_line

from authkeyline import parse_line
from authkeyline._cli import main

GOOD = ed25519_line("good key")
CERT = f"ssh-ed25519-cert-v01@openssh.com {b64(certificate())} cert"


def run(capsys: pytest.CaptureFixture[str], *args: str, stdin: str = "") -> tuple[int, str, str]:
    import sys

    old = sys.stdin
    sys.stdin = io.StringIO(stdin)
    try:
        code = main(list(args))
    finally:
        sys.stdin = old
    out, err = capsys.readouterr()
    return code, out, err


def test_listing_from_stdin(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(capsys, stdin=f"# c\n{GOOD}\n\nno-pty {CERT}\n")
    key = parse_line(GOOD).public_key()
    assert code == 0 and err == ""
    assert out.splitlines() == [
        f"256 {key.fingerprint()} good key (ED25519)",
        f"256 {parse_line(CERT).fingerprint()} cert (ED25519-CERT)",
    ]


def test_md5_listing_and_files(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    path = tmp_path / "authorized_keys"
    path.write_text(GOOD + "\n")
    code, out, _ = run(capsys, "-E", "md5", str(path), "-")
    assert code == 0
    assert out == f"256 {parse_line(GOOD).fingerprint('md5')} good key (ED25519)\n"


def test_broken_lines_go_to_stderr_and_exit_1(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(capsys, stdin=f"{GOOD}\nbogus {GOOD}\n")
    assert code == 1
    assert err == "-:2: unknown option 'bogus'\n"
    assert out.count("\n") == 1


def test_check_reports_only_problems(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(capsys, "--check", stdin=GOOD) == (0, "", "")
    code, out, err = run(capsys, "--check", stdin=f"{GOOD}\nssh-ed25519\n")
    assert (code, out, err) == (1, "", "-:2: missing key blob\n")


def test_json_report(capsys: pytest.CaptureFixture[str]) -> None:
    sk = "sk-ssh-ed25519@openssh.com"
    from keyfactory import blob

    text = f'restrict,command="a b" {GOOD}\n{CERT}\n{sk} {b64(blob(sk, "ed25519-sk"))}\n'
    code, out, _ = run(capsys, "--json", stdin=text)
    report = json.loads(out)
    assert code == 0 and [entry["line"] for entry in report] == [1, 2, 3]
    assert report[0]["options"] == [["restrict", None], ["command", "a b"]]
    assert report[0]["fingerprint"] == parse_line(GOOD).fingerprint()
    assert report[0]["bits"] == 256 and report[0]["comment"] == "good key"
    cert = report[1]["certificate"]
    assert cert["type"] == "user" and cert["principals"] == ["alice"]
    assert cert["extensions"] == ["permit-pty"] and cert["signature_type"] == "ssh-ed25519"
    assert cert["ca_fingerprint"].startswith("SHA256:")
    assert report[2]["application"] == "ssh:" and "certificate" not in report[2]


def test_empty_comment_reads_no_comment(capsys: pytest.CaptureFixture[str]) -> None:
    _, out, _ = run(capsys, stdin=" ".join(GOOD.split()[:2]))
    assert out.endswith(" no comment (ED25519)\n")
