"""Command line: list the keys of authorized_keys files like ``ssh-keygen -l``, or lint them."""

from __future__ import annotations

import argparse
import base64
import contextlib
import errno
import json
import os
import sys
from collections.abc import Sequence
from typing import Any, Literal, TextIO

from ._codec import check_file, parse_line
from ._errors import AuthKeyError
from ._listing import escape, keygen_comment
from ._model import AuthorizedKey
from ._records import PublicKey


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line; return 1 when a line is broken, 2 when a file cannot be read.

    Usage errors also exit with status 2, through argparse.
    """
    parser = argparse.ArgumentParser(
        prog="authkeyline",
        description="List or check the keys of OpenSSH authorized_keys files.",
        epilog="exit status: 0 when every line is fine, 1 when a line is broken, 2 when a "
        "file cannot be read or the arguments are wrong",
    )
    parser.add_argument("files", nargs="*", metavar="FILE", help="files to read, - for stdin")
    parser.add_argument(
        "-E", dest="hash", choices=["sha256", "md5"], default="sha256", help="fingerprint hash"
    )
    parser.add_argument("--json", action="store_true", help="print the keys as JSON")
    parser.add_argument("--check", action="store_true", help="only report broken lines")
    args = parser.parse_args(argv)
    status = [0]
    try:
        _run(args, status)
    except OSError as exc:
        # The reader went away (| head): stop quietly, as ssh-keygen does.
        if not isinstance(exc, BrokenPipeError) and exc.errno not in (errno.EPIPE, errno.EINVAL):
            raise
        _silence()
    return status[0]


def _run(args: argparse.Namespace, status: list[int]) -> None:
    report: list[dict[str, Any]] = []
    for name in args.files or ["-"]:
        try:
            text = _read(name)
        except OSError as exc:
            # The status comes first: the write may fail when the reader has gone.
            status[0] = 2
            _write(sys.stderr, f"authkeyline: {name}: {exc.strerror or exc}")
            continue
        problems = {problem.line: problem.message for problem in check_file(text)}
        if problems:
            status[0] = max(status[0], 1)
        for number, message in problems.items():
            _write(sys.stderr, f"{name}:{number}: {message}")
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
                report.append(_as_json(name, number, raw, key, args.hash))
            else:
                _write(sys.stdout, _listing(raw, key, args.hash))
    if args.json:
        _write(sys.stdout, json.dumps(report, indent=2))


def _silence() -> None:
    """Point the standard streams at the null device so the final flush cannot fail."""
    null = os.open(os.devnull, os.O_WRONLY)
    for stream in (sys.stdout, sys.stderr):
        # A stream that is not a real file, as under a test runner, is left alone.
        with contextlib.suppress(OSError, ValueError, AttributeError):
            os.dup2(null, stream.fileno())
    os.close(null)


def _read(name: str) -> str:
    """Bytes that are not UTF-8 survive as surrogates until the output escapes them."""
    if name == "-":
        stream = getattr(sys.stdin, "buffer", None)
        return sys.stdin.read() if stream is None else _decode(stream.read())
    with open(name, "rb") as handle:
        return _decode(handle.read())


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="surrogateescape")


def _write(stream: TextIO | None, text: str) -> None:
    if stream is None:
        return  # started with the stream closed (>&-), so there is nobody to tell
    raw = getattr(stream, "buffer", None)
    if raw is None:
        stream.write(text + "\n")
        return
    stream.flush()
    raw.write(text.encode("utf-8", errors="surrogateescape") + b"\n")
    raw.flush()


def _listing(raw: str, key: AuthorizedKey, hash: Literal["sha256", "md5"]) -> str:
    public = key.public_key()
    comment = keygen_comment(raw) or "no comment"
    return escape(f"{public.bits} {public.fingerprint(hash)} {comment} ({public.short_type})")


def _text(value: str) -> str:
    """Valid Unicode for JSON: a byte that is not UTF-8 becomes U+FFFD."""
    return value.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def _as_json(
    name: str, number: int, raw: str, key: AuthorizedKey, hash: Literal["sha256", "md5"]
) -> dict[str, Any]:
    public = key.public_key()
    entry: dict[str, Any] = {
        "file": _text(name),
        "line": number,
        "options": [
            [_text(o.name), None if o.value is None else _text(o.value)] for o in key.options
        ],
        "key_type": key.key_type,
        "bits": public.bits,
        "fingerprint": public.fingerprint(hash),
        "comment": _text(key.comment),
    }
    if _text(raw) != raw:
        # The exact bytes of the line, since U+FFFD cannot give back the byte it replaced.
        entry["line_base64"] = base64.b64encode(raw.encode("utf-8", "surrogateescape")).decode()
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
