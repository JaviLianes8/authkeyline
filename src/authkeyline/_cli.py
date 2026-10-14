"""Command line: list the keys of authorized_keys files like ``ssh-keygen -l``, or lint them."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any, Literal, TextIO

from ._codec import check_file, parse_line
from ._errors import AuthKeyError
from ._model import AuthorizedKey
from ._records import PublicKey


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line; return 1 when a line is broken, 2 when a file cannot be read."""
    parser = argparse.ArgumentParser(
        prog="authkeyline",
        description="List or check the keys of OpenSSH authorized_keys files.",
    )
    parser.add_argument("files", nargs="*", metavar="FILE", help="files to read, - for stdin")
    parser.add_argument("-E", dest="hash", choices=["sha256", "md5"], default="sha256")
    parser.add_argument("--json", action="store_true", help="print the keys as JSON")
    parser.add_argument("--check", action="store_true", help="only report broken lines")
    args = parser.parse_args(argv)
    names = args.files or ["-"]
    status = 0
    report: list[dict[str, Any]] = []
    for name in names:
        try:
            text = _read(name)
        except OSError as exc:
            _write(sys.stderr, f"authkeyline: {name}: {exc.strerror or exc}")
            status = 2
            continue
        problems = {problem.line: problem.message for problem in check_file(text)}
        for number, message in problems.items():
            _write(sys.stderr, f"{name}:{number}: {message}")
        if problems:
            status = max(status, 1)
        if args.check:
            continue
        for number, raw in enumerate(text.split("\n"), start=1):
            if number in problems:
                continue
            try:
                key = parse_line(raw)
            except AuthKeyError:
                continue  # blank or comment line
            if args.json:
                report.append(_as_json(name, number, key, args.hash))
            else:
                _write(sys.stdout, _listing(key, args.hash))
    if args.json:
        _write(sys.stdout, json.dumps(report, indent=2))
    return status


def _read(name: str) -> str:
    """Bytes that are not UTF-8 survive as surrogates and are written back unchanged."""
    if name == "-":
        stream = getattr(sys.stdin, "buffer", None)
        return sys.stdin.read() if stream is None else _decode(stream.read())
    with open(name, "rb") as handle:
        return _decode(handle.read())


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="surrogateescape")


def _write(stream: TextIO, text: str) -> None:
    raw = getattr(stream, "buffer", None)
    if raw is None:
        stream.write(text + "\n")
        return
    stream.flush()
    raw.write(text.encode("utf-8", errors="surrogateescape") + b"\n")
    raw.flush()


def _listing(key: AuthorizedKey, hash: Literal["sha256", "md5"]) -> str:
    public = key.public_key()
    # ssh-keygen -l reads lines up to the first CR, so the shown comment stops there too.
    comment = key.comment.split("\r", 1)[0] or "no comment"
    return f"{public.bits} {public.fingerprint(hash)} {comment} ({public.short_type})"


def _as_json(
    name: str, number: int, key: AuthorizedKey, hash: Literal["sha256", "md5"]
) -> dict[str, Any]:
    public = key.public_key()
    entry: dict[str, Any] = {
        "file": name,
        "line": number,
        "options": [[option.name, option.value] for option in key.options],
        "key_type": key.key_type,
        "bits": public.bits,
        "fingerprint": public.fingerprint(hash),
        "comment": key.comment,
    }
    if public.application is not None:
        entry["application"] = public.application
    if public.certificate is not None:
        entry["certificate"] = _certificate(public, hash)
    return entry


def _certificate(public: PublicKey, hash: Literal["sha256", "md5"]) -> dict[str, Any]:
    cert = public.certificate
    assert cert is not None
    return {
        "type": cert.cert_type,
        "serial": cert.serial,
        "key_id": cert.key_id,
        "principals": list(cert.principals),
        "valid_after": cert.valid_after,
        "valid_before": cert.valid_before,
        "critical_options": [name for name, _ in cert.critical_options],
        "extensions": [name for name, _ in cert.extensions],
        "ca_fingerprint": cert.ca_key.fingerprint(hash),
        "signature_type": cert.signature_type,
    }
