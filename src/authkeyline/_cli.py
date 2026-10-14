"""Command line: list the keys of authorized_keys files like ``ssh-keygen -l``, or lint them."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any, Literal

from ._codec import check_file, parse_line
from ._errors import AuthKeyError
from ._model import AuthorizedKey
from ._records import PublicKey


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line; return the exit status (1 when a line is broken)."""
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
    failed = False
    report: list[dict[str, Any]] = []
    for name in names:
        text = _read(name)
        problems = {problem.line: problem.message for problem in check_file(text)}
        for number, message in problems.items():
            print(f"{name}:{number}: {message}", file=sys.stderr)
        failed = failed or bool(problems)
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
                print(_listing(key, args.hash))
    if args.json:
        print(json.dumps(report, indent=2))
    return 1 if failed else 0


def _read(name: str) -> str:
    if name == "-":
        return sys.stdin.read()
    with open(name, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _listing(key: AuthorizedKey, hash: Literal["sha256", "md5"]) -> str:
    public = key.public_key()
    comment = key.comment or "no comment"
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
