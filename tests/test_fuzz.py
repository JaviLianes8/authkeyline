"""Seeded fuzz and properties: hostile text never crashes, hangs, leaks or reads two ways."""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import random
import time

import pytest
from keyfactory import b64, blob, certificate, fields, string
from sshd_corpus import broken_blob, corpus, keys

from authkeyline import AuthKeyError, build_line, check_file, parse_file, parse_line

SEEDS = [7, 2026, 31337]
ALPHABET = ' \t\r\n\0\v,="\\#:/*[]-_.+aAzZ09\u00e9\u2603\udcff'
SECRET = "S3CR3T"


def hostile(rng: random.Random) -> str:
    pieces = ["ssh-ed25519 ", "restrict,", 'command="', 'environment="', "AAAA", "no-pty "]
    out = []
    for _ in range(rng.randrange(1, 12)):
        out.append(rng.choice(pieces) if rng.random() < 0.3 else rng.choice(ALPHABET))
    return "".join(out)


def outcome(line: str) -> str:
    try:
        parse_line(line)
    except AuthKeyError as error:
        assert len(str(error)) < 300 and error.line is None
        return "error"
    return "ok"


@pytest.mark.parametrize("seed", SEEDS)
def test_hostile_text_raises_only_short_auth_key_errors(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(20_000):
        outcome(hostile(rng))


@pytest.mark.parametrize("seed", SEEDS)
def test_damaged_blobs_raise_only_auth_key_errors(seed: int) -> None:
    rng = random.Random(seed)
    pool = keys()
    for _ in range(3_000):
        key_type, raw = rng.choice(pool)
        outcome(f"{key_type} {broken_blob(rng, raw)}")
        cut = rng.randrange(len(raw))
        outcome(f"{key_type} {b64(raw[:cut] + bytes(rng.randrange(256) for _ in range(9)))}")


@pytest.mark.parametrize("seed", SEEDS)
def test_files_read_the_same_line_by_line(seed: int) -> None:
    rng = random.Random(seed)
    lines = corpus(seed, 600, [])
    for _ in range(200):
        text = "\n".join(rng.sample(lines, rng.randrange(1, 8)))
        problems = check_file(text)
        try:
            found = parse_file(text)
        except AuthKeyError as error:
            assert problems and (error.line, error.reason) == (
                problems[0].line,
                problems[0].message,
            )
        else:
            assert not problems
            keys_by_line = [parse_line(line) for line in text.split("\n") if outcome(line) == "ok"]
            assert found == keys_by_line


@pytest.mark.parametrize("seed", SEEDS)
def test_accepted_lines_rebuild_to_the_same_record_or_are_refused(seed: int) -> None:
    built = 0
    for line in corpus(seed, 3_000, []):
        if outcome(line) != "ok":
            continue
        key = parse_line(line)
        try:
            again = build_line(key)
        except AuthKeyError:
            # A built line never holds CR or NUL, which a read line may carry.
            texts = [key.comment, key.key_base64, *(option.value or "" for option in key.options)]
            assert any("\r" in text or "\0" in text for text in texts) or any(
                (option.value or "").endswith("\\") for option in key.options
            ), line
            continue
        assert parse_line(again) == key
        built += 1
    assert built > 500


@pytest.mark.parametrize("seed", SEEDS)
def test_messages_never_quote_an_environment_value(seed: int) -> None:
    rng = random.Random(seed)
    tail = "ssh-ed25519 " + b64(blob("ssh-ed25519", "ed25519"))
    for _ in range(3_000):
        name = rng.choice(["A", "1-x", "", "B C", "x" * 50, "A\u00e9"])
        value = SECRET + hostile(rng).replace('"', "")
        head = rng.choice(["", "bogus,", 'command="a",command="b",', "restrict,"])
        end = rng.choice(['"', "", '"x', '",'])
        problems = check_file(f'{head}environment="{name}={value}{end} {tail}')
        assert all(SECRET not in problem.message for problem in problems)


def _seconds(build: object, size: int) -> float:
    assert callable(build)
    text = build(size)
    start = time.perf_counter()
    with contextlib.suppress(AuthKeyError):
        parse_line(text)
    return time.perf_counter() - start


SHAPES = {
    "flags": lambda n: ",".join(["no-pty"] * n) + " ssh-ed25519 AAAA",
    "escapes": lambda n: 'command="' + '\\"' * n + '" ssh-ed25519 AAAA',
    "environment": lambda n: ",".join(f'environment="V{i}=1"' for i in range(n)) + " x",
    "commas": lambda n: "," * n + "restrict ssh-ed25519 AAAA",
    "blob": lambda n: "ssh-ed25519 " + "A" * (4 * n),
    "blanks": lambda n: " " * n + "ssh-ed25519" + "\t" * n + "AAAA" + " " * n,
    "quote": lambda n: 'command="' + "x" * n,
    "comment": lambda n: "ssh-ed25519 " + b64(blob("ssh-ed25519", "ed25519")) + " c" * n,
}


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_reading_time_grows_linearly(shape: str) -> None:
    small = min(_seconds(SHAPES[shape], 20_000) for _ in range(3))
    large = min(_seconds(SHAPES[shape], 80_000) for _ in range(3))
    assert large < 8 * small + 0.05, (shape, small, large)


def test_certificate_fields_survive_random_principals() -> None:
    rng = random.Random(5)
    for _ in range(300):
        texts = (hostile(rng).replace("\0", "") for _ in range(rng.randrange(4)))
        names = tuple(text.replace("\udcff", "") for text in texts)
        data = certificate(principals=names, key_fields=fields("ed25519"))
        cert = parse_line(f"ssh-ed25519-cert-v01@openssh.com {b64(data)}").public_key()
        assert cert.certificate is not None
        assert cert.certificate.principals == names


def test_a_valid_blob_survives_base64_whitespace_and_keeps_its_fingerprint() -> None:
    raw = string("ssh-ed25519") + fields("ed25519")
    text = base64.b64encode(raw).decode()
    key = parse_line(f"ssh-ed25519 {text}")
    spaced = dataclasses.replace(key, key_base64=text[:10] + "\v\f" + text[10:])
    assert spaced.fingerprint() == key.fingerprint()
